"""
paraminer.py 
==================
Multi-oracle hidden parameter discovery scanner.
Single-file, stdlib-only. Linux / macOS / Termux (Android).

ОСНОВНЫЕ ВОЗМОЖНОСТИ:
  • 5 независимых оракулов (diff, time, reflection, error, cache-key)
  • Streaming output: находки печатаются СРАЗУ при подтверждении
  • Pre-flight check: автоматически детектит CDN-кэш, OAuth-strict, WAF
  • Rate-limit auto-detect (429, Cloudflare, AWS WAF) + sticky backoff
  • Reflection context analyzer (классифицирует место рефлексии)
  • Auto-pivot: новые endpoint'ы из reflection → recursive scan
  • Welch's t-test для time-oracle (статистически чистый p-value)
  • Termux compatible (auto color, ASCII-only output mode)

Подробная справка: python3 paraminer.py --help
"""

import argparse, gzip, hashlib, json, math, os, queue, random, re, socket, socketserver, ssl
import statistics, string, sys, threading, time, urllib.parse, zlib
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler

# Playwright проверяется лениво через _check_playwright() — см. ниже.
# Если не установлен — DOM-oracle просто отключится с предупреждением.

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


# ============================================================================
#  ANSI COLORS
# ============================================================================

class C:
    RESET, BOLD = '\033[0m', '\033[1m'
    GREEN, YELLOW, CYAN, RED, DIM = '\033[32m', '\033[33m', '\033[36m', '\033[31m', '\033[2m'
    @classmethod
    def disable(cls):
        for k in ('RESET', 'BOLD', 'GREEN', 'YELLOW', 'CYAN', 'RED', 'DIM'):
            setattr(cls, k, '')


def auto_color_setup(force_disable=False):
    if force_disable: C.disable(); return
    if os.environ.get('NO_COLOR'): C.disable(); return
    if os.environ.get('TERM') == 'dumb': C.disable(); return
    try:
        if not sys.stderr.isatty(): C.disable()
    except Exception: C.disable()


# ============================================================================
#  HTTP CLIENT
# ============================================================================

class Resp:
    __slots__ = ('status', 'headers', 'body', 'elapsed', 'ttfb', 'error')
    def __init__(self, status=0, headers=None, body=b'', elapsed=0.0,
                 ttfb=0.0, error=None):
        self.status = status; self.headers = headers or {}
        self.body = body; self.elapsed = elapsed
        # ttfb = время до первого байта ответа. Это серверная обработка +
        # network RTT, БЕЗ времени на скачивание тела. Гораздо чище для
        # time-oracle, потому что не зависит от размера ответа.
        self.ttfb = ttfb
        self.error = error
    @property
    def length(self): return len(self.body)
    @property
    def text(self):
        ct = self.headers.get('content-type', '')
        m = re.search(r'charset=([\w-]+)', ct)
        enc = m.group(1) if m else 'utf-8'
        try: return self.body.decode(enc, errors='replace')
        except LookupError: return self.body.decode('utf-8', errors='replace')


def _decode_body(body_bytes, headers):
    enc = headers.get('content-encoding', '').lower()
    try:
        if 'gzip' in enc: return gzip.decompress(body_bytes)
        if 'deflate' in enc:
            try: return zlib.decompress(body_bytes)
            except zlib.error: return zlib.decompress(body_bytes, -zlib.MAX_WBITS)
    except Exception: pass
    return body_bytes


class _GlobalRateLimiter:
  
    def __init__(self):
        self.rps = 0.0          # 0 = выключен
        self._lock = threading.Lock()
        self._tokens = 0.0
        self._last = time.monotonic()
        self._capacity = 1.0

    def configure(self, rps):
        with self._lock:
            self.rps = float(rps or 0)
            # небольшой burst-capacity, но не больше rps и не меньше 1
            self._capacity = max(1.0, min(self.rps, 5.0)) if self.rps else 1.0
            self._tokens = self._capacity
            self._last = time.monotonic()

    def wait(self):
        if self.rps <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self._capacity,
                                   self._tokens + (now - self._last) * self.rps)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # сколько ждать до следующего токена
                deficit = 1.0 - self._tokens
                sleep_for = deficit / self.rps
            time.sleep(min(sleep_for, 1.0))


RATE_LIMITER = _GlobalRateLimiter()


def http_request(method, url, headers=None, body=None, timeout=15, proxy=None):
    RATE_LIMITER.wait()
    headers = dict(headers or {})
    parsed = urllib.parse.urlsplit(url)
    if not parsed.scheme: return Resp(error='bad-url')

    target_host = parsed.hostname
    target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    full_path = parsed.path or '/'
    if parsed.query: full_path += '?' + parsed.query

    headers.setdefault('Host', parsed.netloc)
    headers.setdefault('User-Agent',
                       'Mozilla/5.0 (X11; Linux x86_64) paraminer/0.5')
    headers.setdefault('Accept', '*/*')
    headers.setdefault('Accept-Encoding', 'gzip, deflate')
    headers.setdefault('Connection', 'close')

    if isinstance(body, str): body = body.encode('utf-8')
    if body is not None: headers.setdefault('Content-Length', str(len(body)))

    t0 = time.perf_counter()
    try:
        if proxy:
            p = urllib.parse.urlsplit(proxy)
            if parsed.scheme == 'https':
                conn = HTTPSConnection(p.hostname, p.port or 8080,
                                       timeout=timeout, context=SSL_CTX)
                conn.set_tunnel(parsed.hostname, parsed.port or 443)
            else:
                conn = HTTPConnection(p.hostname, p.port or 8080, timeout=timeout)
                full_path = url
        else:
            if parsed.scheme == 'https':
                conn = HTTPSConnection(target_host, target_port,
                                       timeout=timeout, context=SSL_CTX)
            else:
                conn = HTTPConnection(target_host, target_port, timeout=timeout)

        conn.request(method, full_path, body=body, headers=headers)
        r = conn.getresponse()
        # TTFB: момент, когда мы получили status+headers (но ещё не тело).
        # Это лучшая аппроксимация "время до первого байта" доступная в stdlib
        # http.client без копания во внутренностях socket.
        ttfb = time.perf_counter() - t0
        raw = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        decoded = _decode_body(raw, hdrs)
        elapsed = time.perf_counter() - t0
        conn.close()
        return Resp(status=r.status, headers=hdrs, body=decoded,
                    elapsed=elapsed, ttfb=ttfb)
    except Exception as e:
        return Resp(elapsed=time.perf_counter() - t0, error=str(e))


# ============================================================================
#  REQUEST TEMPLATING
# ============================================================================

def rand_canary(length=8):
    return 'cn' + ''.join(random.choices(string.ascii_lowercase + string.digits,
                                         k=length))


def build_request(base, injection, mode):
    method = base['method']; url = base['url']
    headers = dict(base['headers']); body = base['body']

    if mode == 'query':
        parsed = urllib.parse.urlsplit(url)
        existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        for k, v in injection.items(): existing.append((k, v))
        new_q = urllib.parse.urlencode(existing, doseq=True)
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                       parsed.path, new_q, parsed.fragment))
    elif mode == 'form':
        existing = urllib.parse.parse_qsl(
            body.decode('utf-8', errors='replace') if isinstance(body, bytes)
            else (body or ''), keep_blank_values=True)
        for k, v in injection.items(): existing.append((k, v))
        body = urllib.parse.urlencode(existing, doseq=True)
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    elif mode == 'json':
        try: payload = json.loads(body) if body else {}
        except Exception: payload = {}
        if not isinstance(payload, dict): payload = {}
        payload.update(injection)
        body = json.dumps(payload)
        headers['Content-Type'] = 'application/json'
    elif mode == 'headers':
        for k, v in injection.items():
            safe = re.sub(r'[^A-Za-z0-9-]', '-', k)
            headers[safe] = v
    return method, url, headers, body


# ============================================================================
#  STATISTICS — Welch's t-test, Mann-Whitney U, Modified Z-score
# ============================================================================

def welch_ttest(sample_a, sample_b):
    n_a, n_b = len(sample_a), len(sample_b)
    if n_a < 2 or n_b < 2: return 0.0, 0.0, 1.0
    mean_a, mean_b = statistics.mean(sample_a), statistics.mean(sample_b)
    var_a, var_b = statistics.variance(sample_a), statistics.variance(sample_b)
    if var_a == 0 and var_b == 0:
        return (float('inf') if mean_b > mean_a else 0.0, 0.0,
                0.0 if mean_b > mean_a else 1.0)
    se = math.sqrt(var_a / n_a + var_b / n_b)
    if se == 0: return 0.0, 0.0, 1.0
    t = (mean_b - mean_a) / se
    num = (var_a / n_a + var_b / n_b) ** 2
    den = ((var_a / n_a) ** 2 / max(n_a - 1, 1) +
           (var_b / n_b) ** 2 / max(n_b - 1, 1))
    df = num / den if den > 0 else n_a + n_b - 2
    p = 0.5 * math.erfc(t / math.sqrt(2))
    return t, df, p


def _rankdata(values):
    """Среднее ранжирование с обработкой ties. Stdlib-only."""
    n = len(values)
    indexed = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and values[indexed[j + 1]] == values[indexed[i]]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0  # средний ранг для ties (1-based)
        for k in range(i, j + 1):
            ranks[indexed[k]] = avg_rank
        i = j + 1
    return ranks


def mannwhitney_u(sample_a, sample_b):
    """Mann-Whitney U test (rank-sum). Non-parametric, robust to non-normal
    distributions — что критично для network timings, которые right-skewed.

    Возвращает: (u_statistic, p_value, effect_size)
    - u_statistic: U-statistic (полезен для отладки)
    - p_value: вероятность что выборки из одного распределения (нулевая гипотеза)
    - effect_size: rank-biserial correlation в [-1, 1].
                   Положительный = b > a (probe медленнее baseline)
                   Отрицательный = b < a (probe быстрее baseline)
                   Модуль > 0.3 = средний эффект, > 0.5 = сильный
    """
    n_a, n_b = len(sample_a), len(sample_b)
    if n_a < 3 or n_b < 1: return 0.0, 1.0, 0.0

    combined = list(sample_a) + list(sample_b)
    ranks = _rankdata(combined)
    rank_sum_a = sum(ranks[:n_a])

    u_a = rank_sum_a - n_a * (n_a + 1) / 2.0
    u_b = n_a * n_b - u_a
    u = min(u_a, u_b)

    # Normal approximation для p-value (точна при n_a + n_b >= 10).
    # Continuity correction: -0.5
    mean_u = n_a * n_b / 2.0
    # Учёт ties в дисперсии (упрощённо, без полной коррекции ties — для
    # network timings это редко критично):
    var_u = n_a * n_b * (n_a + n_b + 1) / 12.0
    if var_u <= 0: return u, 1.0, 0.0

    z = (u - mean_u + 0.5) / math.sqrt(var_u)
    # Two-sided p-value через erfc
    p = math.erfc(abs(z) / math.sqrt(2))

    # Effect size (rank-biserial): direction probe vs baseline
    # u_b > u_a означает что выборка b имеет более высокие ранги (= медленнее)
    effect = (u_b - u_a) / (n_a * n_b)  # ∈ [-1, 1]

    return u, p, effect


def modified_z_score(value, baseline_median, baseline_mad):
    """Modified Z-score (Iglewicz-Hoaglin, 1993). Робастный аналог Z-score
    через MAD. NIST рекомендует |z_mod| > 3.5 как порог outlier-detection. На это в основном я полагался.

    Константа 0.6745 = Φ в -1 (0.75), приводит шкалу к совместимости с обычным Z
    для нормального распределения.
    """
    if baseline_mad <= 0: return 0.0
    return 0.6745 * (value - baseline_median) / baseline_mad


def adaptive_noise_threshold(median, mad):
    """Adaptive thresholding для time-oracle на основе шумности baseline.
    Возвращает модификатор p_value_threshold: чем шумнее таргет, тем строже
    мы должны быть с time-сигналом (требуем меньший p_value).

    Логика: на шумных серверах случайные колебания таймингов могут давать
    статистически значимые p-values от пары outlier'ов. Поднимая порог,
    мы избегаем false positives на нестабильных таргетах.
    """
    if median <= 0: return 1.0
    noise_ratio = mad / median
    if noise_ratio > 0.30:  # очень шумно
        return 0.01     # требуем p < 0.0001 (если базовый 0.001)
    elif noise_ratio > 0.15:  # умеренный шум
        return 0.1      # требуем p < 0.0001 от базового 0.001
    elif noise_ratio > 0.08:  # лёгкий шум
        return 0.5
    return 1.0          # таргет стабилен — используем базовый порог


# ============================================================================
#  RATE-LIMIT DETECTION
# ============================================================================

_WAF_BODY_MARKERS = re.compile(
    r'(just a moment|attention required|access denied|'
    r'cloudflare ray id|cf-error|akamai reference|'
    r'request blocked|security check|please verify|'
    r'incapsula incident|imperva|sucuri website firewall|'
    r'aws waf|blocked by your security policy|'
    r'rate.?limit(?:ed|ing)?|too many requests|'
    r'checking your browser|ddos protection)',
    re.IGNORECASE)


def detect_rate_limit(resp):
    """Возвращает (severity 0-3, reason, retry_after_seconds)."""
    if resp is None: return 0, None, 0
    if resp.error:
        err = str(resp.error).lower()
        if any(k in err for k in ('timed out', 'connection reset',
                                   'connection refused', 'broken pipe')):
            return 1, f'connection error: {resp.error[:60]}', 0
        return 0, None, 0

    status, headers = resp.status, resp.headers
    retry_after = 0
    ra = headers.get('retry-after', '')
    if ra:
        try: retry_after = int(ra)
        except ValueError: retry_after = 30

    if status == 429:
        return 2, 'HTTP 429 (rate limit)', max(retry_after, 5)

    cf_mitigated = headers.get('cf-mitigated', '').lower()
    if cf_mitigated in ('challenge', 'block'):
        return 3, f'cf-mitigated={cf_mitigated}', max(retry_after, 30)

    if status == 403:
        if 'cloudflare' in headers.get('server', '').lower() or 'cf-ray' in headers:
            try:
                if _WAF_BODY_MARKERS.search(resp.text[:4000]):
                    return 3, 'HTTP 403 + Cloudflare WAF marker', max(retry_after, 30)
            except Exception: pass
            return 2, 'HTTP 403 + cf-ray (WAF)', max(retry_after, 15)

    if status == 503:
        try:
            if _WAF_BODY_MARKERS.search(resp.text[:4000]):
                return 3, 'HTTP 503 + WAF marker', max(retry_after, 30)
        except Exception: pass
        return 1, 'HTTP 503', max(retry_after, 5)

    if status in (418, 420, 444):
        return 3, f'HTTP {status} (anti-bot)', max(retry_after, 30)

    rl_rem = headers.get('x-ratelimit-remaining',
                         headers.get('x-rate-limit-remaining', ''))
    if rl_rem and rl_rem.isdigit() and int(rl_rem) == 0:
        return 2, 'x-ratelimit-remaining=0', max(retry_after, 5)

    if headers.get('x-amzn-waf-action', '') in ('BLOCK', 'COUNT'):
        return 3, 'AWS WAF blocked', max(retry_after, 30)

    if status == 200 and 0 < resp.length < 50000:
        try:
            if _WAF_BODY_MARKERS.search(resp.text[:4000]):
                return 3, 'WAF challenge HTML', max(retry_after, 30)
        except Exception: pass

    return 0, None, 0


class RateLimitGovernor:
    def __init__(self, initial_threads, min_threads=1, enabled=True, printer=None):
        self.enabled = enabled
        self.initial_threads = initial_threads
        self.current_threads = initial_threads
        self.min_threads = min_threads
        self.printer = printer
        self.window = deque(maxlen=30)
        self.consecutive_429 = 0
        self.paused_until = 0.0
        self.lock = threading.RLock()
        self.semaphore = threading.Semaphore(initial_threads)
        self.total_rate_limits = 0
        self.last_throttle_time = 0
        self.recovery_streak = 0

    def _log(self, msg, level='warn'):
        if self.printer: self.printer.emit_log(msg, level)
        else: sys.stderr.write(msg + '\n')

    def acquire(self):
        if not self.enabled: return
        while True:
            with self.lock: wait = self.paused_until - time.time()
            if wait <= 0: break
            time.sleep(min(wait, 1.0))
        self.semaphore.acquire()

    def release(self):
        if self.enabled: self.semaphore.release()

    def observe(self, resp):
        if not self.enabled: return
        severity, reason, retry_after = detect_rate_limit(resp)
        with self.lock:
            self.window.append(severity)
            if severity >= 2:
                self.total_rate_limits += 1
                self.consecutive_429 += 1
                self.recovery_streak = 0
            elif severity == 0:
                self.consecutive_429 = 0
                self.recovery_streak += 1
            self._maybe_throttle(severity, reason, retry_after)
            self._maybe_recover()

    def _maybe_throttle(self, severity, reason, retry_after):
        if severity == 0: return
        if len(self.window) < 5: return
        rl_count = sum(1 for s in self.window if s >= 2)
        crit_count = sum(1 for s in self.window if s >= 3)
        rate = rl_count / len(self.window)

        if severity == 3 or self.consecutive_429 >= 5 or crit_count >= 3:
            self._apply_throttle(self.min_threads, max(retry_after, 30),
                                 f'CRITICAL: {reason}')
            return
        if rate >= 0.2 or self.consecutive_429 >= 3:
            new_t = max(self.min_threads, self.current_threads // 2)
            self._apply_throttle(new_t, max(retry_after, 10),
                                 f'HARD: {reason} (rate={rate:.0%})')
            return
        if rate >= 0.05 and severity >= 2:
            new_t = max(self.min_threads, self.current_threads - 1)
            self._apply_throttle(new_t, max(retry_after, 3),
                                 f'SOFT: {reason} (rate={rate:.0%})')

    def _apply_throttle(self, new_threads, pause, reason):
        now = time.time()
        if now - self.last_throttle_time < 5: return
        self.last_throttle_time = now
        delta = self.current_threads - new_threads
        for _ in range(delta):
            if not self.semaphore.acquire(blocking=False):
                threading.Thread(target=self._eat_slot, daemon=True).start()
        if new_threads < self.current_threads or pause > 0:
            self.current_threads = new_threads
            self.paused_until = now + pause
            self._log(f'[!] Rate-limit: {reason} -> threads={new_threads}, '
                      f'pause={pause}s', 'warn')

    def _eat_slot(self):
        self.semaphore.acquire()

    def _maybe_recover(self):
        if self.recovery_streak < 50: return
        if self.current_threads >= max(2, self.initial_threads // 2): return
        self.current_threads += 1
        self.semaphore.release()
        self.recovery_streak = 0
        self._log(f'[+] Recovery: threads -> {self.current_threads}', 'info')


# ============================================================================
#  PRE-FLIGHT CHECK (NEW v0.5) — детект CDN/WAF/non-reactive target
# ============================================================================

# CDN/cache headers, обнаружение которых = «между нами и приложением кэш»
_CDN_HEADERS = {
    'cf-cache-status':  'Cloudflare',
    'cf-ray':           'Cloudflare',
    'x-cache':          'Generic CDN (varies)',
    'x-served-by':      'Fastly/Varnish',
    'x-cache-hits':     'Varnish/Fastly',
    'x-amz-cf-id':      'CloudFront',
    'x-amz-cf-pop':     'CloudFront',
    'x-akamai-transformed': 'Akamai',
    'akamai-cache-status': 'Akamai',
    'x-edge-location':  'AWS Edge',
    'x-azure-ref':      'Azure Front Door',
    'fastly-debug-digest': 'Fastly',
}

# Параметры, которые САМЫЕ распространённые на любом веб-app
_PROBE_PARAMS = ['debug', 'admin', 'test', 'id', 'q', 'redirect',
                 'callback', 'lang', 'page', 'search', 'preview', 'mode']


class PreflightReport:
    def __init__(self):
        self.cdn_detected = []      # list of (header_name, vendor)
        self.cache_hit_ratio = 0.0  # % response с HIT
        self.identical_responses = 0  # сколько probe вернули байт-в-байт baseline
        self.reactive_params = []   # параметры, которые ИЗМЕНИЛИ response
        self.waf_detected = False
        self.waf_vendor = None
        self.oauth_redirect = False
        self.recommendations = []

    @property
    def is_non_reactive(self):
        """Target не реагирует на параметры (CDN-кэш / OAuth-strict / WAF-drop)."""
        return len(self.reactive_params) == 0 and self.identical_responses >= 4

    def summary(self):
        lines = []
        if self.cdn_detected:
            vendors = ', '.join(set(v for _, v in self.cdn_detected))
            lines.append(f'CDN: {vendors}')
        if self.cache_hit_ratio > 0:
            lines.append(f'Cache HIT ratio: {self.cache_hit_ratio:.0%}')
        if self.waf_detected:
            lines.append(f'WAF: {self.waf_vendor}')
        if self.oauth_redirect:
            lines.append('OAuth-style strict validation detected')
        if self.reactive_params:
            lines.append(f'Reactive probe params: {self.reactive_params}')
        else:
            lines.append('NO probe params triggered response change')
        return lines


def preflight_check(base_req, mode, timeout=15, proxy=None, printer=None):
    """
    Быстрая диагностика target'а до основного скана.
    Возвращает (PreflightReport, baseline_responses).
    """
    def emit(msg, level='info'):
        if printer: printer.emit_log(msg, level)
        else: sys.stderr.write(msg + '\n')

    emit('[*] Pre-flight check: probing target reactivity...')
    report = PreflightReport()

    # Шаг 1: 3 baseline-запроса (без параметров)
    baselines = []
    for _ in range(3):
        m, u, h, b = build_request(base_req, {}, mode)
        r = http_request(m, u, h, b, timeout=timeout, proxy=proxy)
        if not r.error: baselines.append(r)
    if not baselines:
        emit('[!] Pre-flight: target unreachable', 'err')
        return report, []

    # Шаг 2: анализ baseline headers на CDN/WAF
    for r in baselines:
        for hdr, vendor in _CDN_HEADERS.items():
            if hdr in r.headers:
                report.cdn_detected.append((hdr, vendor))
                # cache-status: HIT?
                if 'cache' in hdr.lower():
                    v = r.headers[hdr].upper()
                    if 'HIT' in v:
                        report.cache_hit_ratio += 1.0 / len(baselines)

        # WAF-vendor detection
        if 'cf-ray' in r.headers or 'cloudflare' in r.headers.get('server', '').lower():
            report.waf_detected = True
            report.waf_vendor = 'Cloudflare'
        elif 'x-amzn-waf' in str(r.headers) or 'awselb' in r.headers.get('server', '').lower():
            report.waf_detected = True
            report.waf_vendor = 'AWS WAF'
        elif 'akamai' in str(r.headers).lower():
            report.waf_detected = True
            report.waf_vendor = 'Akamai'

    # Дедуп CDN
    report.cdn_detected = list(set(report.cdn_detected))

    # Baseline check на OAuth-style redirect
    for r in baselines:
        if r.status in (301, 302, 303, 307, 308):
            loc = r.headers.get('location', '')
            if any(k in loc.lower() for k in ('oauth', 'sso', 'auth', 'login',
                                              'authorize', 'token')):
                report.oauth_redirect = True
                break

    # Шаг 3: probe — шлём известные параметры с нонс-значениями,
    # смотрим, изменился ли response относительно baseline
    baseline_len = statistics.median([r.length for r in baselines])
    baseline_status = baselines[0].status
    baseline_body_sample = baselines[0].text[:2000] if baselines[0].body else ''

    identical_count = 0
    for pname in _PROBE_PARAMS:
        canary = rand_canary()
        m, u, h, b = build_request(base_req, {pname: canary}, mode)
        r = http_request(m, u, h, b, timeout=timeout, proxy=proxy)
        if r.error: continue

        # Status changed?
        status_diff = (r.status != baseline_status)
        # Length changed >3%?
        length_diff = (abs(r.length - baseline_len) > max(20, 0.03 * baseline_len))
        # Body changed in first 2K?
        body_diff = (r.text[:2000] != baseline_body_sample if r.body else False)
        # Canary reflected?
        reflected = (canary in r.text if r.body else False)

        if status_diff or length_diff or body_diff or reflected:
            report.reactive_params.append(pname)
        else:
            identical_count += 1

    report.identical_responses = identical_count

    # Шаг 4: рекомендации
    if report.is_non_reactive:
        causes = []
        if report.cache_hit_ratio >= 0.5:
            causes.append('Aggressive CDN caching (params don\'t reach backend)')
        if report.oauth_redirect:
            causes.append('OAuth strict-validation (unknown params -> redirect)')
        if report.waf_detected:
            causes.append(f'{report.waf_vendor} may be silently dropping unknown params')
        if not causes:
            causes.append('Backend ignores query string entirely (static page?)')
        report.recommendations.append(f'CAUSE: {"; ".join(causes)}')
        report.recommendations.append(
            'TRY: scan a different endpoint (API/form/search, not login/static)')
        report.recommendations.append(
            'TRY: --pivot to discover related endpoints automatically')
        report.recommendations.append(
            'OR: use --force-scan to scan anyway (slow, may yield nothing)')

    if report.waf_detected and not report.is_non_reactive:
        report.recommendations.append(
            f'WARN: {report.waf_vendor} detected. Use -c 2 and slow down.')

    return report, baselines


# ============================================================================
#  REFLECTION CONTEXT ANALYZER
# ============================================================================

CONTEXT_INFO = {
    'html_text':            (95, 'Reflected XSS', '<svg/onload=alert(1)>'),
    'html_attr_unquoted':   (95, 'XSS via attr break', '" onmouseover=alert(1) x="'),
    'html_attr_double':     (90, 'XSS via " escape', '"><svg/onload=alert(1)>'),
    'html_attr_single':     (90, "XSS via ' escape", "'><svg/onload=alert(1)>"),
    'js_string_double':     (88, 'XSS via JS string break (")', '";alert(1);//'),
    'js_string_single':     (88, "XSS via JS string break (')", "';alert(1);//"),
    'js_template':          (92, 'XSS via JS template literal', '${alert(1)}'),
    'script_block':         (95, 'Direct JS execution', ';alert(1)//'),
    'css_block':            (50, 'CSS injection', '}*{background:url(//evil/?x=)}'),
    'url_path':             (75, 'Open Redirect / SSRF', '//evil.com'),
    'url_query':            (50, 'URL query reflection', 'combine w/ hdr inj'),
    'url_host':             (85, 'Open Redirect via host', 'evil.com'),
    'meta_url_canonical':   (78, 'Canonical poisoning / SEO', '//evil/'),
    'meta_url_og':          (75, 'OG meta injection (SSRF)', '//internal/'),
    'href_attr':            (80, 'Open Redirect via <a href>', 'javascript:alert(1)'),
    'src_attr':             (88, 'XSS via src= injection',
                             'data:text/html,<script>alert(1)</script>'),
    'header_value':         (70, 'CRLF / Cache poisoning', '\\r\\nSet-Cookie:x=y'),
    'comment':              (40, 'HTML comment context', '--><script>alert(1)</script>'),
    'json_value':           (60, 'JSON value reflection', '\\";alert(1);//'),
    'unknown':              (30, 'Unknown context', 'inspect manually'),
}


def analyze_reflection_context(text, canary):
    contexts = []
    start = 0
    while True:
        pos = text.find(canary, start)
        if pos == -1: break
        before = text[max(0, pos - 80):pos]
        after = text[pos + len(canary):pos + len(canary) + 80]
        snippet = (before[-60:] + '<<' + canary + '>>' + after[:60]).replace('\n', ' ')
        ctx = _classify_context(before, after, text, pos)
        contexts.append((ctx, snippet, pos))
        start = pos + len(canary)
    contexts.sort(key=lambda c: -CONTEXT_INFO.get(c[0], (0,))[0])
    return contexts


def _classify_context(before, after, full_text, pos):
    last_script_open = before.rfind('<script')
    last_script_close = before.rfind('</script>')
    if last_script_open > last_script_close:
        b_in_script = before[last_script_open:]
        if _inside_quote(b_in_script, '"'):  return 'js_string_double'
        if _inside_quote(b_in_script, "'"):  return 'js_string_single'
        if _inside_quote(b_in_script, '`'):  return 'js_template'
        return 'script_block'

    last_style_open = before.rfind('<style')
    last_style_close = before.rfind('</style>')
    if last_style_open > last_style_close: return 'css_block'

    last_comment_open = before.rfind('<!--')
    last_comment_close = before.rfind('-->')
    if last_comment_open > last_comment_close: return 'comment'

    last_lt = before.rfind('<')
    last_gt = before.rfind('>')
    inside_tag = last_lt > last_gt

    if inside_tag:
        tag_frag = before[last_lt:]
        tag_match = re.match(r'<\s*([a-zA-Z][\w-]*)', tag_frag)
        tag_name = tag_match.group(1).lower() if tag_match else ''
        attr_ctx = _detect_attr_context(tag_frag, after)

        if tag_name == 'meta':
            full_tag = tag_frag + after.split('>', 1)[0]
            if re.search(r'(property|name)="(og:url|twitter:url|canonical)"',
                         full_tag, re.I):
                return 'meta_url_canonical'
            if re.search(r'(property|name)="(og:image|og:video|og:audio|'
                         r'twitter:image|og:.*url)"', full_tag, re.I):
                return 'meta_url_og'

        if tag_name == 'link':
            full_tag = tag_frag + after.split('>', 1)[0]
            if re.search(r'rel=["\']?canonical', full_tag, re.I):
                return 'meta_url_canonical'

        if attr_ctx['attr_name'] == 'href': return 'href_attr'
        if attr_ctx['attr_name'] in ('src', 'action', 'data', 'formaction'):
            return 'src_attr'
        if attr_ctx['quote'] == '"':  return 'html_attr_double'
        if attr_ctx['quote'] == "'":  return 'html_attr_single'
        if attr_ctx['attr_name']:     return 'html_attr_unquoted'

    if re.search(r':\s*"$', before[-30:]) or re.search(r':\s*$', before[-10:]):
        return 'json_value'
    return 'html_text'


def _inside_quote(text, quote_char):
    count = 0; i = 0
    while i < len(text):
        c = text[i]
        if c == '\\' and i + 1 < len(text):
            i += 2; continue
        if c == quote_char: count += 1
        i += 1
    return count % 2 == 1


def _detect_attr_context(tag_frag, after):
    cleaned = re.sub(r'\s+[\w-]+="[^"]*"', '', tag_frag)
    cleaned = re.sub(r"\s+[\w-]+='[^']*'", '', cleaned)
    cleaned = re.sub(r'\s+[\w-]+=[\w-]+(?=\s|$)', '', cleaned)
    m = re.search(r'\s+([\w-]+)\s*=\s*(["\']?)$', cleaned)
    if m: return {'attr_name': m.group(1).lower(), 'quote': m.group(2) or None}
    return {'attr_name': '', 'quote': None}


# ============================================================================
#  PIVOT EXTRACTION — FIXED
# ============================================================================

def extract_pivot_urls(resp_text, canary, base_url):
    """
    Найти URL'ы в response, в которых попала канарейка.
    fix: ищем канарейку В ЦЕЛОМ response, потом смотрим контекст,
    а не только в URL-attribute regex. Это ловит JS-redirects и data-attrs.
    """
    pivots = set()
    if canary not in resp_text: return pivots

    base_host = urllib.parse.urlsplit(base_url).netloc

    # Method 1: канарейка прямо в href/src/action/data-X attribute
    for m in re.finditer(
        r'(?:href|src|action|content|formaction|data-[\w-]+)\s*=\s*["\']?'
        r'([^"\'\s<>]*' + re.escape(canary) + r'[^"\'\s<>]*)', resp_text, re.I):
        url = m.group(1)
        pivot = _normalize_pivot(url, canary, base_url, base_host)
        if pivot: pivots.add(pivot)

    # Method 2: канарейка внутри JS-строки с URL-like контекстом
    # Ищем 'string with canary' где string выглядит как URL
    for m in re.finditer(
        r'["\']((?:https?:|/)[^"\']*' + re.escape(canary) + r'[^"\']*)["\']',
        resp_text):
        url = m.group(1)
        pivot = _normalize_pivot(url, canary, base_url, base_host)
        if pivot: pivots.add(pivot)

    # Method 3: канарейка попала в meta property=og:url content
    for m in re.finditer(
        r'<meta\s+[^>]*content\s*=\s*["\']([^"\']*' + re.escape(canary) +
        r'[^"\']*)["\']', resp_text, re.I):
        url = m.group(1)
        pivot = _normalize_pivot(url, canary, base_url, base_host)
        if pivot: pivots.add(pivot)

    # Method 4: window.location / location.href = "..." с канарейкой
    for m in re.finditer(
        r'(?:location\.(?:href|replace|assign)\s*=\s*|window\.open\s*\()'
        r'\s*["\']([^"\']*' + re.escape(canary) + r'[^"\']*)["\']',
        resp_text, re.I):
        url = m.group(1)
        pivot = _normalize_pivot(url, canary, base_url, base_host)
        if pivot: pivots.add(pivot)

    return pivots


def _normalize_pivot(url, canary, base_url, base_host):
    """Нормализует URL-пивот: удаляет канарейку, резолвит relative, проверяет origin."""
    # Удалить query-param с канарейкой, если она там
    clean = re.sub(r'[?&][\w\[\]-]*=[^&]*' + re.escape(canary) +
                   r'[^&]*(?=&|$)', '', url)
    # Если канарейка осталась в path — заменить на нейтральное X
    clean = clean.replace(canary, 'X')

    try:
        absolute = urllib.parse.urljoin(base_url, clean)
        new_host = urllib.parse.urlsplit(absolute).netloc
        # Same-origin only
        if new_host and new_host != base_host: return None
        # Не пивотить на тот же URL
        base_path = urllib.parse.urlsplit(base_url).path.rstrip('/')
        new_path = urllib.parse.urlsplit(absolute).path.rstrip('/')
        if new_path == base_path: return None
        # Только http/https
        if not absolute.startswith(('http://', 'https://')): return None
        return absolute
    except Exception:
        return None




# ============================================================================
#  ORACLES
# ============================================================================

class Calibration:
    def __init__(self):
        self.statuses, self.lengths, self.times, self.bodies = [], [], [], []
        self.total_times = []  # elapsed (TTFB + body read) — для информации
        self.headers_samples = []
        self.stable_lines = None

    def absorb(self, resp):
        self.statuses.append(resp.status)
        self.lengths.append(resp.length)
        # times = TTFB (server processing + RTT, без скачивания тела).
        # Это убирает шум от размера ответа: параметр, который изменил длину
        # на 100KB, не создаёт фантомного time-signal от bandwidth.
        # Fallback на elapsed для старых Resp без ttfb (selftest, и т.п.)
        self.times.append(resp.ttfb if resp.ttfb > 0 else resp.elapsed)
        self.total_times.append(resp.elapsed)
        self.headers_samples.append(dict(resp.headers))
        try: self.bodies.append(resp.text)
        except Exception: self.bodies.append('')

    def finalize(self):
        if not self.bodies:
            self.stable_lines = set(); return
        first_lines = set(self.bodies[0].splitlines())
        for b in self.bodies[1:]: first_lines &= set(b.splitlines())
        self.stable_lines = first_lines

    @property
    def time_median(self): return statistics.median(self.times) if self.times else 0.0
    @property
    def time_mad(self):
        if len(self.times) < 2: return 0.0
        m = self.time_median
        return max(statistics.median([abs(t - m) for t in self.times]), 0.001)
    @property
    def length_set(self): return set(self.lengths)
    @property
    def status_set(self): return set(self.statuses)
    @property
    def cache_status_baseline(self):
        keys = ['cf-cache-status', 'x-cache', 'x-cache-status', 'x-served-by', 'age']
        seen = {}
        for h in self.headers_samples:
            for k in keys:
                if k in h: seen.setdefault(k, set()).add(h[k])
        return seen

    @property
    def server_timing_metrics(self):
        """
        Парсит Server-Timing из baseline. Возвращает dict:
        {metric_name: {'samples': [floats], 'median': float, 'mad': float}}
        Server-Timing формат: 'db;dur=12.3, cache;dur=0.5, app;dur=4.1'
        """
        metrics = {}
        for h in self.headers_samples:
            st = h.get('server-timing', '')
            if not st: continue
            # Парсим: разделители ',' и ';'
            for entry in st.split(','):
                entry = entry.strip()
                # Извлекаем имя метрики и dur
                parts = entry.split(';')
                name = parts[0].strip()
                if not name: continue
                dur_val = None
                for p in parts[1:]:
                    p = p.strip()
                    if p.startswith('dur='):
                        try: dur_val = float(p[4:])
                        except ValueError: pass
                if dur_val is not None:
                    metrics.setdefault(name, []).append(dur_val)
        # Compute median + MAD per metric
        result = {}
        for name, samples in metrics.items():
            if len(samples) < 2: continue
            med = statistics.median(samples)
            mad = max(statistics.median([abs(s - med) for s in samples]), 0.1)
            result[name] = {'samples': samples, 'median': med, 'mad': mad}
        return result

    @property
    def cookies_baseline(self):
        """Множество (name, value) cookies из baseline."""
        cookies = set()
        for h in self.headers_samples:
            sc = h.get('set-cookie', '')
            if not sc: continue
            # Парсим простой формат: name=value; attrs
            for ck in sc.split(','):
                ck = ck.split(';')[0].strip()
                if '=' in ck:
                    cookies.add(ck)
        return cookies

    @property
    def inline_states_baseline(self):
        """
        Множества значений inline-state для каждого ключа из baseline.
        Возвращает {state_key: set(serialized_states)}.
        Если SSR-данные меняются каждый запрос (timestamps, IDs) — baseline
        будет иметь несколько значений, и это нормально (diff oracle сравнит).
        """
        all_states = {}
        for body in self.bodies:
            if not body: continue
            states = extract_inline_state(body)
            for k, v in states.items():
                all_states.setdefault(k, set()).add(v)
        return all_states


def diff_oracle(resp, calib, exclude_error_statuses=False):
    if resp.status == 0: return 0.0, None
    if resp.status in (429, 418, 420, 444): return 0.0, None
    if resp.status not in calib.status_set:
        if exclude_error_statuses and resp.status in (401, 403, 404, 429,
                                                     500, 502, 503, 504):
            pass
        else:
            return 1.0, f'status={resp.status} (baseline: {sorted(calib.status_set)})'
    if resp.length not in calib.length_set:
        ml = statistics.median(calib.lengths)
        if abs(resp.length - ml) > max(20, 0.03 * ml):
            return 0.7, f'length={resp.length} (median: {int(ml)})'
    try:
        new_lines = set(resp.text.splitlines()) - calib.stable_lines
        non_trivial = [l for l in new_lines
                       if len(l.strip()) > 5
                       and not re.search(
                           r'(nonce|csrf|timestamp|"id":\s*"[a-f0-9-]+"|'
                           r'<meta\s+name="(csrf|ts|rid)"|content="[a-f0-9]{16,}|'
                           r'cf-ray|x-request-id|x-trace-id)', l, re.I)]
        if non_trivial:
            score = min(0.6 + 0.05 * len(non_trivial), 0.95)
            return score, f'line-diff: {non_trivial[0][:120]!r}'
    except Exception: pass
    return 0.0, None


def time_oracle_ttest(probe_times, calib, p_threshold=
    if not probe_times or len(calib.times) < 3: return 0.0, None

    # Adaptive: tighten p-threshold on noisy targets
    noise_mult = adaptive_noise_threshold(calib.time_median, calib.time_mad)
    effective_threshold = p_threshold * noise_mult

    _u, p, effect = mannwhitney_u(calib.times, probe_times)

    # effect > 0 means probe slower than baseline (we care about slowdowns)
    if p < effective_threshold and effect > 0:
        # Score scales with statistical significance, capped at 0.9
        score = 0.6 + min(0.3, 0.3 * (1 - math.log10(max(p, 1e-12)) / -12))
        med = statistics.median(probe_times)
        z_mod = modified_z_score(med, calib.time_median, calib.time_mad)
        return score, (f'time={med*1000:.0f}ms vs baseline '
                       f'{calib.time_median*1000:.0f}ms '
                       f'(Z_mod={z_mod:.1f}, p={p:.1e}, effect={effect:.2f})')
    return 0.0, None


def reflection_oracle(resp, canaries):
    if not resp.body: return 0.0, None, []
    text = resp.text
    found_contexts = []
    for cn in canaries:
        if cn in text:
            ctxs = analyze_reflection_context(text, cn)
            found_contexts.append((cn, ctxs))
    for cn in canaries:
        for hk, hv in resp.headers.items():
            if cn in hv:
                found_contexts.append((cn, [('header_value',
                                             f'{hk}: ...<<{cn}>>...', -1)]))
    if not found_contexts: return 0.0, None, []
    max_p = 0
    for cn, ctxs in found_contexts:
        for ctx_name, _, _ in ctxs:
            p = CONTEXT_INFO.get(ctx_name, (0,))[0]
            if p > max_p: max_p = p
    score = min(0.85 + (max_p / 100) * 0.12, 0.97)
    cn0, ctxs0 = found_contexts[0]
    if ctxs0:
        reason = f'canary {cn0!r} reflected -> context={ctxs0[0][0]!r}'
    else:
        reason = f'canary {cn0!r} reflected'
    return score, reason, found_contexts


def cache_key_oracle(resp, calib):
    keys = ['cf-cache-status', 'x-cache', 'x-cache-status', 'age']
    baseline_seen = calib.cache_status_baseline
    for k in keys:
        if k in resp.headers:
            v = resp.headers[k]
            baseline_vals = baseline_seen.get(k, set())
            if v not in baseline_vals and baseline_vals:
                if 'MISS' in v.upper() or 'BYPASS' in v.upper():
                    return 0.65, f'{k}: {v} (baseline: {sorted(baseline_vals)})'
                return 0.45, f'{k} changed: {v} (baseline: {sorted(baseline_vals)})'
    return 0.0, None


def server_timing_oracle(resp, calib):
    """
    NEW v0.5.2: Server-Timing oracle.
    Парсит Server-Timing header (e.g. 'db;dur=12.3, cache;dur=0.5')
    и сравнивает каждую метрику с baseline через MAD.
    
    Работает СКВОЗЬ CDN-кэш: даже если HTML идентичный из кэша,
    Server-Timing часто отдаёт реальные backend-метрики.
    """
    st = resp.headers.get('server-timing', '')
    if not st: return 0.0, None
    baseline = calib.server_timing_metrics
    if not baseline: return 0.0, None

    anomalies = []
    for entry in st.split(','):
        entry = entry.strip()
        parts = entry.split(';')
        name = parts[0].strip()
        if not name or name not in baseline: continue
        dur_val = None
        for p in parts[1:]:
            p = p.strip()
            if p.startswith('dur='):
                try: dur_val = float(p[4:])
                except ValueError: pass
        if dur_val is None: continue

        base_info = baseline[name]
        med = base_info['median']
        mad = base_info['mad']
        if mad <= 0: continue
        deviation = (dur_val - med) / mad
        # >5 MAD = сильный сигнал, >3 MAD = подозрительный
        if abs(deviation) > 3:
            anomalies.append((name, dur_val, med, deviation))

    if not anomalies: return 0.0, None
    # Score по самой большой аномалии
    strongest = max(anomalies, key=lambda a: abs(a[3]))
    name, val, med, dev = strongest
    score = min(0.5 + abs(dev) * 0.05, 0.85)
    return score, (f'server-timing[{name}]={val:.1f}ms vs baseline '
                   f'{med:.1f}ms ({dev:+.1f} MADs)')


def cookie_oracle(resp, calib):
    """
    NEW v0.5.2: детектит изменения в Set-Cookie.
    Если параметр заставил сервер выставить новый cookie / изменить значение —
    это сильный сигнал backend processing, который часто пропускают.
    """
    sc = resp.headers.get('set-cookie', '')
    if not sc: return 0.0, None

    response_cookies = set()
    for ck in sc.split(','):
        ck = ck.split(';')[0].strip()
        if '=' in ck:
            response_cookies.add(ck)

    baseline_cookies = calib.cookies_baseline
    new_cookies = response_cookies - baseline_cookies
    if not new_cookies: return 0.0, None

    # Фильтр псевдо-новых (session-id меняется каждый запрос, это не наш сигнал)
    # Используем эвристику: cookie с длинным random value (>20 chars hex/base64)
    # вероятно session token, не наш indicator
    interesting = []
    for ck in new_cookies:
        name, _, value = ck.partition('=')
        # Не считаем за находку: session-like cookies
        if re.match(r'^[a-fA-F0-9]{20,}$|^[A-Za-z0-9+/=]{30,}$', value):
            continue
        interesting.append(ck)

    if not interesting: return 0.0, None
    sample = interesting[0][:80]
    return 0.7, f'new Set-Cookie: {sample!r}'


# ============================================================================
#  INLINE JS-STATE EXTRACTION (v0.6 — путь 1, без зависимостей)
# ============================================================================

# Паттерны inline-state для популярных SPA-фреймворков
_INLINE_STATE_PATTERNS = [
    # Next.js
    (r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
     'NEXT_DATA', 'json'),
    # Redux / generic __INITIAL_STATE__
    (r'window\.__INITIAL_STATE__\s*=\s*(\{.*?\})\s*;?\s*(?:</script>|window\.|var\s)',
     'INITIAL_STATE', 'json'),
    # Nuxt 2/3
    (r'window\.__NUXT__\s*=\s*(\{.*?\}|\(.*?\)\(.*?\))\s*;?\s*</script>',
     'NUXT', 'json_or_iife'),
    # Apollo
    (r'window\.__APOLLO_STATE__\s*=\s*(\{.*?\})\s*;?\s*(?:</script>|window\.)',
     'APOLLO_STATE', 'json'),
    # Generic preloaded state
    (r'window\.__PRELOADED_STATE__\s*=\s*(\{.*?\})\s*;?\s*(?:</script>|window\.)',
     'PRELOADED_STATE', 'json'),
    # Vuex/Pinia store dump
    (r'window\.__VUEX_STATE__\s*=\s*(\{.*?\})\s*;?\s*(?:</script>|window\.)',
     'VUEX_STATE', 'json'),
    # SSR data
    (r'window\.__SSR_DATA__\s*=\s*(\{.*?\})\s*;?\s*(?:</script>|window\.)',
     'SSR_DATA', 'json'),
    # data-* attributes на root element с JSON
    (r'<(?:div|main|app-root)\s+[^>]*data-app-state=["\']([^"\']+)["\']',
     'DATA_APP_STATE', 'json_quoted'),
    # Inline JSON dumps в <script type="application/json">
    (r'<script[^>]*type=["\']application/json["\'][^>]*>(.*?)</script>',
     'APPLICATION_JSON', 'json'),
]


def extract_inline_state(text):
    """
    Извлекает inline JSON-состояние из HTML-страницы.
    Возвращает dict: {pattern_name: serialized_state_string}.
    Для DOM-diff используется именно сериализованная строка (нормализованная),
    т.к. парсинг JSON может ломаться на сложных объектах.
    """
    states = {}
    for pattern, name, kind in _INLINE_STATE_PATTERNS:
        for match in re.finditer(pattern, text, re.DOTALL):
            raw = match.group(1)
            if kind == 'json_quoted':
                # HTML-entities decode для data-attribute
                raw = (raw.replace('&quot;', '"')
                          .replace('&#34;', '"')
                          .replace('&amp;', '&'))
            elif kind == 'json_or_iife':
                # Nuxt 3 часто IIFE: (function(a,b){return {...}})('x','y')
                # пытаемся вытащить JSON-часть
                if raw.startswith('(function'):
                    m2 = re.search(r'return\s+(\{.*\})', raw, re.DOTALL)
                    if m2: raw = m2.group(1)

            # Нормализуем: пытаемся JSON-parse → re-serialize отсортированно
            try:
                parsed = json.loads(raw)
                normalized = json.dumps(parsed, sort_keys=True,
                                        separators=(',', ':'))
                key = f'{name}_{len(states.get(name, []))}'
                states[key] = normalized
            except (json.JSONDecodeError, ValueError):
                # Если не парсится — используем raw, обрезанный
                # (некоторые SPA сериализуют невалидный JSON с JS-литералами)
                states[f'{name}_raw'] = raw[:2000]

    return states


def js_state_oracle(resp, calib):
    """
    Oracle для inline-state SPA-фреймворков (Next/Nuxt/Redux/Apollo/Vuex).
    Сравнивает извлечённое состояние с baseline.

    Работает там где обычный diff не работает:
    - frontend-rendered SPA с одинаковым HTML-shell
    - страницы где данные в JSON, а не в DOM
    - Hydration-патерны SSR
    """
    if not resp.body: return 0.0, None
    try:
        text = resp.text
    except Exception:
        return 0.0, None

    current_state = extract_inline_state(text)
    if not current_state: return 0.0, None

    baseline_states = calib.inline_states_baseline
    if not baseline_states: return 0.0, None

    # Ищем ключи которые либо новые, либо изменились
    differences = []
    for key, val in current_state.items():
        base_vals = baseline_states.get(key, set())
        if not base_vals:
            # Ключ только в текущем response — слабый сигнал, мог не успеть в baseline
            continue
        if val not in base_vals:
            # Размер diff и его характер
            len_diff = abs(len(val) - len(next(iter(base_vals))))
            differences.append((key, len_diff, val[:200]))

    if not differences: return 0.0, None

    # Score по размеру и количеству diff
    strongest = max(differences, key=lambda d: d[1])
    key, diff_size, sample = strongest
    if diff_size < 5:  # совсем мелкая разница — мог быть просто timestamp
        return 0.0, None
    score = min(0.65 + min(diff_size / 1000, 0.2), 0.88)
    return score, f'js-state[{key}] changed (~{diff_size} bytes diff)'


def semantic_probe_oracle(base_req, param_name, mode, proxy, timeout, governor=None):
    """
   Усиленный error_oracle с семантическими probe-значениями.
    Шлёт параметр с разными типами значений и анализирует distinct response
    signatures. Работает даже там, где random canary не отражается.
    
    Принцип: если бэкенд РЕАЛЬНО обрабатывает параметр, то integer/null/array/
    string дадут разные ответы. Если не обрабатывает — все ответы одинаковые.
    """
    test_values = [
        ('1', 'int_one'),
        ('0', 'int_zero'),
        ('-1', 'int_neg'),
        ('999999999', 'int_huge'),
        ('null', 'null'),
        ('true', 'bool_true'),
        ('[1,2,3]', 'array'),
        ('{"x":1}', 'object'),
        ('A' * 100, 'long_string'),
        ('../etc/passwd', 'path_traversal'),
        ('\'"<>&', 'special_chars'),
    ]
    signatures = []
    timings = []
    for val, label in test_values:
        if governor: governor.acquire()
        r = None
        try:
            m, u, h, b = build_request(base_req, {param_name: val}, mode)
            r = http_request(m, u, h, b, timeout=timeout, proxy=proxy)
        finally:
            if governor:
                governor.release()
                governor.observe(r)
        if r is None or r.error:
            signatures.append(('ERR',))
            continue
        # Signature: status + length-bucket + has-error + content-type-cat
        ct = r.headers.get('content-type', '')[:20]
        bucket = r.length // 100
        has_err = bool(re.search(r'(error|invalid|exception|traceback|illegal)',
                                  r.text[:2000], re.I)) if r.body else False
        sig = (r.status, bucket, has_err, ct)
        signatures.append(sig)
        timings.append(r.ttfb if r.ttfb > 0 else r.elapsed)

    distinct = len(set(signatures))
    if distinct >= 4:
        return 0.7, f'semantic probe: {distinct}/{len(test_values)} distinct signatures'
    if distinct >= 3:
        return 0.5, f'semantic probe: {distinct}/{len(test_values)} distinct signatures'

    # Timing variance — ОЧЕНЬ слабый и шумный сигнал через интернет.
    # порог (outlier>4, штук>=2) ловил обычный сетевой джиттер и давал
    # 0.45 на КАЖДЫЙ параметр. Теперь: требуем редкие сильные выбросы и
    # достаточную стабильность baseline-таймингов самих проб, иначе не верим.
    if len(timings) >= 8:
        med = statistics.median(timings)
        mad = max(statistics.median([abs(t - med) for t in timings]), 0.001)
        rel_noise = mad / med if med > 0 else 1.0
        # если сами пробы шумные (rel_noise высокий) — это сеть, не сигнал
        if rel_noise < 0.20:
            strong = sum(1 for t in timings if abs(t - med) / mad > 6)
            if strong >= 3:
                return 0.40, f'semantic probe: timing variance ({strong} strong outliers)'

    return 0.0, None


def header_reflection_oracle(resp, canaries):
места.
  
    if not resp.headers:
        return 0.0, None
    # заголовки, попадание в которые особенно показательно
    hot = ('location', 'set-cookie', 'content-disposition', 'link',
           'refresh', 'content-location')
    for cn in canaries:
        for hk, hv in resp.headers.items():
            if cn in (hv or ''):
                where = hk.lower()
                if where in hot:
                    return 0.85, f'canary reflected in response header {hk!r}'
                return 0.7, f'canary reflected in response header {hk!r}'
    return 0.0, None


def pollution_oracle(base_req, param_name, mode, proxy, timeout,
                     calib, requester=None):
    """HTTP Parameter Pollution / value-confusion oracle.

    Идея: сравниваем три ответа —
      (a) без параметра,
      (b) param=V1,
      (c) param=V1&param=V2 (дубль того же ключа).
    Если (c) отличается от (b) — бэкенд РЕАЛЬНО разбирает этот ключ (берёт
    первое/последнее/массив значений). Для параметров, которые сервер
    игнорирует, дубль ничего не меняет. Работает даже когда одиночный probe
    не отличается от baseline (значение по умолчанию совпало).
    """
    if mode not in ('query', 'form'):
        return 0.0, None
    if requester is None:
        def requester(m, u, h, b):
            return http_request(m, u, h, b, timeout=timeout, proxy=proxy)

    v1 = rand_canary()
    v2 = rand_canary()

    def sig(r):
        if r is None or r.error:
            return None
        # сигнатура устойчива к мелкому динамическому шуму: статус + bucket длины
        return (r.status, r.length // 64)

    # (b) одиночный
    m, u, h, b = build_request(base_req, {param_name: v1}, mode)
    r_single = requester(m, u, h, b)
    # (c) дубль того же ключа — собираем вручную, build_request не делает дублей
    if mode == 'query':
        parsed = urllib.parse.urlsplit(base_req['url'])
        ex = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        ex.append((param_name, v1)); ex.append((param_name, v2))
        q = urllib.parse.urlencode(ex, doseq=True)
        u2 = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                      parsed.path, q, parsed.fragment))
        m2, h2, b2 = base_req['method'], dict(base_req['headers']), base_req['body']
        r_double = requester(m2, u2, h2, b2)
    else:  # form
        body = base_req['body']
        ex = urllib.parse.parse_qsl(
            body.decode('utf-8', 'replace') if isinstance(body, bytes)
            else (body or ''), keep_blank_values=True)
        ex.append((param_name, v1)); ex.append((param_name, v2))
        b2 = urllib.parse.urlencode(ex, doseq=True)
        h2 = dict(base_req['headers'])
        h2['Content-Type'] = 'application/x-www-form-urlencoded'
        r_double = requester(base_req['method'], base_req['url'], h2, b2)

    s_single, s_double = sig(r_single), sig(r_double)
    if s_single is None or s_double is None:
        return 0.0, None
    # baseline-сигнатуры (status + length bucket)
    base_sigs = {(st, ln // 64) for st, ln in
                 zip(calib.statuses, calib.lengths)}

    if s_double != s_single:
        # дубль изменил ответ относительно одиночного — параметр разбирается
        return 0.72, (f'parameter pollution: dup key changed response '
                      f'{s_single} -> {s_double}')
    if s_single not in base_sigs:
        # одиночный уже отличается от baseline — тоже сигнал (slabее)
        return 0.6, f'pollution probe: single value differs from baseline {s_single}'
    return 0.0, None


def boolean_pair_oracle(base_req, param_name, mode, proxy, timeout,
                        requester=None, repeats=3):
    """
    Шлём пару ПРОТИВОПОЛОЖНЫХ значений несколько раз и проверяем, что разница
    между ними СТАБИЛЬНА (не плавает от запроса к запросу). Стабильное
    расхождение = детерминированная реакция бэкенда на значение, а не сетевой
    шум. Это ключевой антидот к false-positiveّам semantic_probe/timing на
    нестабильных таргетах: случайный джиттер не даёт стабильной разницы.
    """
    if mode not in ('query', 'form', 'json'):
        return 0.0, None
    if requester is None:
        def requester(m, u, h, b):
            return http_request(m, u, h, b, timeout=timeout, proxy=proxy)

    pairs = [('1', '0'), ('true', 'false'),
             ('999999999', '-1'), ('valid', 'a' * 64)]

    def sig(r):
        if r is None or r.error:
            return None
        ct = (r.headers.get('content-type', '') or '')[:24]
        return (r.status, r.length // 48, ct)

    stable_pairs = 0
    detail = None
    for va, vb in pairs:
        sigs_a, sigs_b = [], []
        for _ in range(repeats):
            m, u, h, b = build_request(base_req, {param_name: va}, mode)
            sigs_a.append(sig(requester(m, u, h, b)))
            m, u, h, b = build_request(base_req, {param_name: vb}, mode)
            sigs_b.append(sig(requester(m, u, h, b)))
        # обе стороны должны быть внутренне стабильны и отличаться друг от друга
        if (None in sigs_a) or (None in sigs_b):
            continue
        a_stable = len(set(sigs_a)) == 1
        b_stable = len(set(sigs_b)) == 1
        if a_stable and b_stable and sigs_a[0] != sigs_b[0]:
            stable_pairs += 1
            if detail is None:
                detail = f'{va!r}{sigs_a[0]} != {vb!r}{sigs_b[0]}'

    if stable_pairs >= 2:
        return 0.8, f'boolean-pair: {stable_pairs} stable contradictory responses ({detail})'
    if stable_pairs == 1:
        return 0.6, f'boolean-pair: 1 stable contradictory response ({detail})'
    return 0.0, None


def error_oracle(base_req, param_name, mode, proxy, timeout, governor=None):
    test_values = [('A' * 4096, 'long'), ('', 'empty'), ('${{7*7}}', 'tmpl'),
                   ('null', 'null'), ('-1', 'neg'), ('[1,2,3]', 'array')]
    responses = []
    for val, label in test_values:
        if governor: governor.acquire()
        r = None
        try:
            m, u, h, b = build_request(base_req, {param_name: val}, mode)
            r = http_request(m, u, h, b, timeout=timeout, proxy=proxy)
        finally:
            if governor:
                governor.release()
                governor.observe(r)
        if r is None or r.error:
            responses.append(('ERR', (r.error if r else 'no-resp')[:50]))
        else:
            has_err = bool(re.search(r'(error|invalid|exception|traceback)',
                                     r.text[:2000], re.I))
            responses.append((r.status, r.length // 100, has_err))
    distinct = len(set(responses))
    if distinct >= 3: return 0.6, f'distinct error states: {distinct}/6'
    return 0.0, None


def aggregate(*signals):
    p_not = 1.0; reasons = []
    for score, reason in signals:
        if score > 0:
            p_not *= (1 - score); reasons.append(reason)
    return 1 - p_not, reasons


# ============================================================================
#  DOM-DIFF ORACLE (v0.6, optional, requires playwright)
# ============================================================================
#
#  Эта секция требует Playwright. Установка описана в гайде.
#
#  DOM-diff сравнивает не HTTP-response, а финальное состояние страницы
#  ПОСЛЕ выполнения всего клиентского JS. Детектит параметры, которые
#  читает фронтенд (OAuth, SPA, аналитика) и которые невидимы для HTTP-diff.
#
#  ВНИМАНИЕ: DOM-diff в 50-200x медленнее HTTP-diff. Не использовать
#  на больших wordlists (>500 params). Подход:
#    1) Запустить обычный скан с HTTP-оракулами → получить кандидатов
#    2) Прогнать DOM-diff только на кандидатах
#  ИЛИ:
#    Использовать --dom-diff-only на маленьком (50-200) wordlist'е.
# ============================================================================

_PLAYWRIGHT_AVAILABLE = None  # lazy check

def _check_playwright():
    """Возвращает True/False с кэшированием — playwright установлен?"""
    global _PLAYWRIGHT_AVAILABLE
    if _PLAYWRIGHT_AVAILABLE is not None:
        return _PLAYWRIGHT_AVAILABLE
    try:
        from playwright.sync_api import sync_playwright  # noqa
        _PLAYWRIGHT_AVAILABLE = True
    except ImportError:
        _PLAYWRIGHT_AVAILABLE = False
    return _PLAYWRIGHT_AVAILABLE


class DOMSnapshot:
    __slots__ = ('body_hash', 'body_size', 'xhr_calls', 'console_logs',
                 'local_storage', 'session_storage', 'cookies',
                 'final_url', 'title')
    def __init__(self, body_hash='', body_size=0, xhr_calls=None,
                 console_logs=None, local_storage=None, session_storage=None,
                 cookies=None, final_url='', title=''):
        self.body_hash = body_hash
        self.body_size = body_size
        self.xhr_calls = xhr_calls or []
        self.console_logs = console_logs or []
        self.local_storage = local_storage or {}
        self.session_storage = session_storage or {}
        self.cookies = cookies or {}
        self.final_url = final_url
        self.title = title

    def diff(self, other):
    
        diffs = []
        if self.body_hash != other.body_hash:
            size_change = other.body_size - self.body_size
            diffs.append(('dom_body', f'DOM changed (size diff: {size_change:+d})'))
        if self.final_url != other.final_url:
            diffs.append(('final_url',
                          f'final URL: {self.final_url!r} -> {other.final_url!r}'))
        if self.title != other.title:
            diffs.append(('title', f'title: {self.title!r} -> {other.title!r}'))
        # XHR diff
        my_xhr = {(c['method'], c['url']) for c in self.xhr_calls}
        other_xhr = {(c['method'], c['url']) for c in other.xhr_calls}
        new_xhr = other_xhr - my_xhr
        if new_xhr:
            sample = list(new_xhr)[0]
            diffs.append(('xhr', f'new XHR: {sample[0]} {sample[1][:80]}'))
        # Console diff
        new_logs = [l for l in other.console_logs if l not in self.console_logs]
        if new_logs:
            diffs.append(('console', f'new console: {new_logs[0][:80]!r}'))
        # Storage diff
        for storage_name, my_st, other_st in [
            ('localStorage', self.local_storage, other.local_storage),
            ('sessionStorage', self.session_storage, other.session_storage),
        ]:
            new_keys = set(other_st.keys()) - set(my_st.keys())
            if new_keys:
                k = list(new_keys)[0]
                diffs.append((storage_name,
                              f'new {storage_name}[{k!r}]={other_st[k][:60]!r}'))
            changed = [k for k in my_st if k in other_st and my_st[k] != other_st[k]]
            if changed:
                k = changed[0]
                diffs.append((f'{storage_name}_changed',
                              f'{storage_name}[{k!r}] changed'))
        # Cookies
        new_cookies = set(other.cookies.keys()) - set(self.cookies.keys())
        if new_cookies:
            k = list(new_cookies)[0]
            diffs.append(('cookie',
                          f'new cookie {k!r}={other.cookies[k][:60]!r}'))
        return diffs


class DOMScanner:
    """
    Запускает headless Chrome, делает snapshot страницы для baseline и probes.
    Один browser-instance для всей сессии (быстрее).
    """
    def __init__(self, timeout=20, headless=True, user_agent=None):
        if not _check_playwright():
            raise RuntimeError(
                'Playwright не установлен. Установи:\n'
                '  pip install playwright\n'
                '  playwright install chromium')
        from playwright.sync_api import sync_playwright
        self.timeout = timeout * 1000  # playwright в ms
        self.headless = headless
        self.user_agent = user_agent or 'paraminer/0.6 DOMDiff'
        self._pw = None
        self._browser = None
        self._lock = threading.Lock()

    def start(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)

    def stop(self):
        try:
            if self._browser: self._browser.close()
            if self._pw: self._pw.stop()
        except Exception: pass

    def snapshot(self, url):
        """Загружает URL, выполняет JS, возвращает DOMSnapshot."""
        if not self._browser: self.start()
        # Lock — playwright sync API не очень thread-safe
        with self._lock:
            ctx = self._browser.new_context(
                user_agent=self.user_agent,
                ignore_https_errors=True)
            page = ctx.new_page()
            xhr_calls = []
            console_logs = []

            def on_request(request):
                # Перехватываем все XHR/fetch
                if request.resource_type in ('xhr', 'fetch'):
                    xhr_calls.append({'method': request.method,
                                      'url': request.url})

            def on_console(msg):
                console_logs.append(f'{msg.type}: {msg.text}'[:300])

            page.on('request', on_request)
            page.on('console', on_console)

            try:
                page.goto(url, timeout=self.timeout, wait_until='networkidle')
            except Exception as e:
                try:
                    # Если networkidle не дождался — пробуем domcontentloaded
                    page.goto(url, timeout=self.timeout,
                              wait_until='domcontentloaded')
                except Exception:
                    ctx.close()
                    return None

            # Дать JS-у дополнительно отработать
            try: page.wait_for_load_state('networkidle', timeout=3000)
            except Exception: pass

            try:
                body_html = page.evaluate('document.body ? '
                                           'document.body.outerHTML : ""')
                title = page.evaluate('document.title || ""')
                final_url = page.url
                local_st = page.evaluate('''() => {
                    const r = {};
                    try { for (let i = 0; i < localStorage.length; i++) {
                        const k = localStorage.key(i);
                        r[k] = localStorage.getItem(k);
                    }} catch(e){}
                    return r;
                }''')
                session_st = page.evaluate('''() => {
                    const r = {};
                    try { for (let i = 0; i < sessionStorage.length; i++) {
                        const k = sessionStorage.key(i);
                        r[k] = sessionStorage.getItem(k);
                    }} catch(e){}
                    return r;
                }''')
                cookies_list = ctx.cookies()
                cookies = {c['name']: c['value'] for c in cookies_list}
            except Exception as e:
                ctx.close()
                return None

            import hashlib
            body_hash = hashlib.md5(body_html.encode('utf-8',
                                                     errors='replace')).hexdigest()

            ctx.close()
            return DOMSnapshot(
                body_hash=body_hash,
                body_size=len(body_html),
                xhr_calls=xhr_calls,
                console_logs=console_logs,
                local_storage=local_st,
                session_storage=session_st,
                cookies=cookies,
                final_url=final_url,
                title=title)


def dom_diff_oracle(base_url, param_name, canary, mode, dom_scanner,
                    baseline_snapshot, additional_query=None):
  
  
    if mode != 'query':
        # DOM-diff пока работает только с query-параметрами
        # (для body нужна была бы XHR-инъекция, это другое)
        return 0.0, None

    # Строим URL с inject
    parsed = urllib.parse.urlsplit(base_url)
    existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    existing.append((param_name, canary))
    new_q = urllib.parse.urlencode(existing, doseq=True)
    probe_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                          parsed.path, new_q, parsed.fragment))

    try:
        probe_snapshot = dom_scanner.snapshot(probe_url)
    except Exception as e:
        return 0.0, None
    if probe_snapshot is None: return 0.0, None

    diffs = baseline_snapshot.diff(probe_snapshot)
    if not diffs: return 0.0, None

    def _is_canary_echo_url(u_base, u_probe):
        """True, если разница final_url — это лишь наша же ?param=canary,
        добавленная к тому же пути. Артефакт редиректов на /login и т.п.,
        НЕ сигнал об обработке параметра бэкендом."""
        if not u_probe:
            return False
        if canary not in u_probe and param_name not in u_probe:
            return False
        # выкинуть из probe-URL ровно наш param=canary и сравнить с baseline
        stripped = re.sub(
            r'[?&]' + re.escape(param_name) + r'=' + re.escape(canary)
            + r'(?=&|$)', '', u_probe)
        # подчистить осиротевшие ?/& и финальные разделители
        stripped = stripped.replace('?&', '?').rstrip('?&')
        return stripped.rstrip('/') == (u_base or '').rstrip('/')

    # Фильтр шумных/артефактных diff'ов:
    #  - cookie с session/csrf/token/nonce (меняются каждый запрос)
    #  - final_url, отличающийся ровно на нашу же канарейку (redirect echo)
    interesting = []
    for kind, msg in diffs:
        if kind == 'cookie' and re.search(r'sess|csrf|tok|nonce', msg, re.I):
            continue
        if kind == 'final_url' and _is_canary_echo_url(
                baseline_snapshot.final_url, probe_snapshot.final_url):
            continue
        interesting.append((kind, msg))
    if not interesting: return 0.0, None

    # Канарейка в реально клиентских местах (title/XHR-URL/console) — настоящий
    # сигнал, что фронтенд ПРОЧИТАЛ параметр. URL-bar (final_url) не считается:
    # там канарейка оседает просто потому, что мы её туда положили.
    canary_anywhere = (canary in (probe_snapshot.title or '') or
                       any(canary in c['url'] for c in probe_snapshot.xhr_calls) or
                       any(canary in l for l in probe_snapshot.console_logs))

    # Score: базовый 0.6 + 0.1 за каждый доп. diff. НО body-only diff без
    # других сигналов на динамичной странице — слабый, держим консервативно.
    only_body = all(k in ('dom_body',) for k, _ in interesting)
    base = 0.45 if only_body and not canary_anywhere else 0.6
    score = min(base + 0.1 * (len(interesting) - 1), 0.95)
    if any(k == 'xhr' for k, _ in interesting):
        score = min(score + 0.15, 0.97)
    if canary_anywhere:
        score = min(score + 0.2, 0.98)

    reason_str = '; '.join(f'{t}: {d}' for t, d in interesting[:3])
    return score, f'DOM-diff: {reason_str}'


# ============================================================================
#  STREAMING OUTPUT
# ============================================================================

class StreamPrinter:
    def __init__(self, quiet=False):
        self.quiet = quiet; self.lock = threading.Lock()
        self.last_progress_len = 0
        self.found_count = 0
        self.total_chunks = 0; self.chunks_done = 0
        self.cands_found = 0; self.verified_done = 0; self.verify_total = 0
        self.stage = 'init'; self.governor = None

    def _clear_progress(self):
        if self.last_progress_len > 0:
            sys.stderr.write('\r' + ' ' * self.last_progress_len + '\r')
            sys.stderr.flush(); self.last_progress_len = 0

    def _render_progress(self):
        if self.quiet: return
        gov = ''
        if self.governor and self.governor.enabled and self.governor.total_rate_limits > 0:
            gov = (f' [throttle:t={self.governor.current_threads} '
                   f'rl={self.governor.total_rate_limits}]')
        if self.stage == 'scan':
            line = (f'[*] scan {self.chunks_done}/{self.total_chunks} '
                    f'cand:{self.cands_found} found:{self.found_count}{gov}')
        elif self.stage == 'verify':
            line = (f'[*] verify {self.verified_done}/{self.verify_total} '
                    f'found:{self.found_count}{gov}')
        else: line = ''
        sys.stderr.write('\r' + line + ' ' * 4)
        sys.stderr.flush()
        self.last_progress_len = len(line) + 4

    def update_progress(self, **kwargs):
        with self.lock:
            for k, v in kwargs.items(): setattr(self, k, v)
            self._render_progress()

    def emit_finding(self, finding):
        with self.lock:
            self._clear_progress()
            self.found_count += 1
            score = finding.score
            sc = (C.GREEN if score >= 0.8 else
                  C.YELLOW if score >= 0.6 else C.DIM)
            print(f'{sc}[{score:.2f}]{C.RESET} {C.BOLD}{finding.name}{C.RESET}'
                  f'  {C.DIM}@ {finding.endpoint}{C.RESET}', flush=True)
            for r in finding.reasons:
                print(f'   {C.DIM}|-{C.RESET} {r}', flush=True)
            if finding.contexts:
                for cn, ctxs in finding.contexts[:1]:
                    for ctx_name, snippet, _ in ctxs[:1]:
                        info = CONTEXT_INFO.get(ctx_name, (0, 'unknown', ''))
                        print(f'   {C.DIM}|-{C.RESET} '
                              f'{C.CYAN}context={ctx_name}{C.RESET} -> {info[1]}',
                              flush=True)
                        if info[2]:
                            print(f'      {C.DIM}payload:{C.RESET} {info[2]}',
                                  flush=True)
            if finding.pivot_urls:
                for purl in list(finding.pivot_urls)[:3]:
                    print(f'   {C.DIM}|-{C.RESET} '
                          f'{C.YELLOW}PIVOT URL:{C.RESET} {purl}', flush=True)
            print(flush=True)
            sys.stdout.flush()
            self._render_progress()

    def emit_candidate(self, name, score, reasons, endpoint=None):
        """
        Stage 1 кандидат — лёгкий вывод ДО verify-стадии.
        Печатается АВТОМАТИЧЕСКИ при каждой находке (без флага).
        Маркируется '?' (не подтверждённый), confidence в [].
        """
        with self.lock:
            self._clear_progress()
            ep = endpoint or '?'
            print(f'{C.DIM}[{score:.2f}]?{C.RESET} {name}'
                  f'  {C.DIM}@ {ep}  (candidate, awaiting verify){C.RESET}',
                  flush=True)
            for r in reasons[:1]:
                print(f'   {C.DIM}|- {r}{C.RESET}', flush=True)
            sys.stdout.flush()
            self._render_progress()

    def emit_log(self, msg, level='info'):
        with self.lock:
            self._clear_progress()
            color = {'info': '', 'warn': C.YELLOW, 'err': C.RED}.get(level, '')
            sys.stderr.write(f'{color}{msg}{C.RESET}\n')
            sys.stderr.flush()
            self._render_progress()

    def finish(self):
        with self.lock: self._clear_progress()


# ============================================================================
#  SCANNER
# ============================================================================

class Finding:
    __slots__ = ('name', 'score', 'reasons', 'contexts', 'pivot_urls', 'endpoint')
    def __init__(self, name, score, reasons, contexts=None, pivot_urls=None,
                 endpoint=None):
        self.name = name; self.score = score; self.reasons = reasons
        self.contexts = contexts or []
        self.pivot_urls = pivot_urls or set()
        self.endpoint = endpoint


class Scanner:
    def __init__(self, base_req, mode, proxy=None, timeout=15, chunk_size=25,
                 threads=4, calibration_n=10, confidence_threshold=0.5,
                 verify=True, time_threshold_mads=4.0, quiet=False,
                 max_chunk_hits=8, exclude_error_statuses=False,
                 skip_error_oracle=False, p_value_threshold=0.001,
                 use_cache_oracle=True, enable_pivot=False, printer=None,
                 rate_limit_adapt=True, stream_candidates=True,
                 use_dom_oracle=False, dom_timeout=20,
                 stream_verify=False, stream_verify_cap=500,
                 direct_probe=False):
        self.base_req = base_req; self.mode = mode; self.proxy = proxy
        self.timeout = timeout; self.chunk_size = chunk_size
        self.threads = threads; self.calibration_n = calibration_n
        self.confidence_threshold = confidence_threshold
        self.verify = verify; self.time_threshold_mads = time_threshold_mads
        self.quiet = quiet
        self.max_chunk_hits = max_chunk_hits
        self.exclude_error_statuses = exclude_error_statuses
        self.skip_error_oracle = skip_error_oracle
        self.p_value_threshold = p_value_threshold
        self.use_cache_oracle = use_cache_oracle
        self.enable_pivot = enable_pivot
        self.calib = Calibration()
        self.lock = threading.Lock()
        self.findings = []
        self.adaptive_threads = threads
        self.printer = printer
        self.rate_limit_adapt = rate_limit_adapt
        self.stream_candidates = stream_candidates
        self.governor = None
        # DOM-oracle (опциональный, требует playwright)
        # works only for mode='query' — DOM-diff не имеет смысла для headers/body
        self.use_dom_oracle = use_dom_oracle and mode == 'query'
        self.dom_timeout = dom_timeout
        self.dom_scanner = None
        self.dom_baseline = None
        # Stream-verify: verify-as-you-go вместо batch-verify в конце stage 1
        self.stream_verify = stream_verify and verify
        self.stream_verify_cap = stream_verify_cap
        self._stream_seen = set()  # дедупликация в stream-verify режиме
        self._stream_seen_lock = threading.Lock()
        # Direct-probe режим: обходит chunk-based discovery полностью и гоняет
        # verify_param (со всеми оракулами, включая semantic_probe) по каждому
        # параметру напрямую. Для CDN-кэшированных / non-reactive таргетов, где
        # diff-discovery по чанкам бесполезен.
        self.direct_probe = direct_probe

    def _log(self, msg, level='info'):
        if self.printer and not self.quiet: self.printer.emit_log(msg, level)
        elif not self.quiet: log(msg)

    def _request(self, *args, **kwargs):
        if self.governor: self.governor.acquire()
        r = None
        try: r = http_request(*args, **kwargs)
        finally:
            if self.governor:
                self.governor.release(); self.governor.observe(r)
        return r

    def calibrate(self):
        self._log(f'[*] Calibrating with {self.calibration_n} baseline requests...')
        for _ in range(self.calibration_n):
            m, u, h, b = build_request(self.base_req, {}, self.mode)
            r = http_request(m, u, h, b, timeout=self.timeout, proxy=self.proxy)
            if r.error:
                self._log(f'[!] Baseline error: {r.error}', 'warn'); continue
            sev, reason, _ = detect_rate_limit(r)
            if sev >= 2: self._log(f'[!] Baseline rate-limited: {reason}', 'warn')
            self.calib.absorb(r)
        self.calib.finalize()
        if not self.calib.times: die('Could not establish baseline.')

        rj = self.calib.time_mad / max(self.calib.time_median, 0.001)
        if rj > 0.05 and self.threads > 4:
            self.adaptive_threads = max(2, self.threads // 4)
            self._log(f'[!] Site noisy (jitter={rj:.1%}). '
                      f'threads {self.threads}->{self.adaptive_threads}', 'warn')

        if self.rate_limit_adapt:
            self.governor = RateLimitGovernor(
                initial_threads=self.adaptive_threads, min_threads=1,
                enabled=True, printer=self.printer)
            if self.printer: self.printer.governor = self.governor

        # Noise classification для информативности и адаптивности time-oracle
        noise_ratio = self.calib.time_mad / max(self.calib.time_median, 0.001)
        if noise_ratio > 0.30:   noise_label = 'VERY NOISY'
        elif noise_ratio > 0.15: noise_label = 'noisy'
        elif noise_ratio > 0.08: noise_label = 'mild jitter'
        else:                     noise_label = 'stable'

        # mean total time для сравнения сколько занимает download body
        total_med = statistics.median(self.calib.total_times) if self.calib.total_times else 0
        ttfb_share = self.calib.time_median / total_med if total_med > 0 else 1.0

        self._log(f'[+] Baseline: status={sorted(self.calib.status_set)}, '
                  f'TTFB={self.calib.time_median*1000:.1f}ms '
                  f'(mad={self.calib.time_mad*1000:.1f}ms, {noise_label}), '
                  f'total={total_med*1000:.1f}ms, '
                  f'len={min(self.calib.lengths)}-{max(self.calib.lengths)}')

        if noise_ratio > 0.30:
            self._log(f'[!] High timing noise (MAD/median={noise_ratio:.2f}). '
                      f'Time-oracle threshold tightened automatically.', 'warn')

    def _init_dom_oracle(self):
        if not self.use_dom_oracle: return
        if self.dom_scanner is not None: return  # уже инициализировано
        try:
            self.dom_scanner = DOMScanner(timeout=self.dom_timeout)
            self._log('[*] DOM-oracle: capturing baseline snapshot...')
            self.dom_baseline = self.dom_scanner.snapshot(self.base_req['url'])
            if self.dom_baseline is None:
                self._log('[!] DOM-oracle: baseline snapshot failed, '
                          'disabling oracle', 'warn')
                self._dom_oracle_cleanup()
            else:
                self._log('[+] DOM-oracle: baseline ready')
        except Exception as e:
            self._log(f'[!] DOM-oracle init failed: {e}. Disabling.', 'warn')
            self._dom_oracle_cleanup()

    def _dom_oracle_cleanup(self):
        """Stop DOMScanner and disable the oracle. Safe to call multiple times."""
        if self.dom_scanner is not None:
            try: self.dom_scanner.stop()
            except Exception: pass
        self.dom_scanner = None
        self.dom_baseline = None
        self.use_dom_oracle = False

    def test_chunk(self, params_chunk, depth=0):
        canaries = {p: rand_canary() for p in params_chunk}
        m, u, h, b = build_request(self.base_req, canaries, self.mode)
        r = self._request(m, u, h, b, timeout=self.timeout, proxy=self.proxy)
        if r.error: return []
        sev, _, _ = detect_rate_limit(r)
        if sev >= 2: return []
        d = diff_oracle(r, self.calib, self.exclude_error_statuses)
        f_score, f_reason, _ = reflection_oracle(r, list(canaries.values()))
        total, reasons = aggregate(d, (f_score, f_reason))
        if total < self.confidence_threshold * 0.6: return []
        if len(params_chunk) == 1:
            return [(params_chunk[0], total, reasons)]
        if depth >= 8: return []
        mid = len(params_chunk) // 2
        result = (self.test_chunk(params_chunk[:mid], depth + 1) +
                  self.test_chunk(params_chunk[mid:], depth + 1))
        # тут было `return []` — целый чанк выбрасывался, если из него
        # вылезало больше max_chunk_hits кандидатов. На шумных/echo-таргетах это
        # уничтожало реальные находки. Теперь обрезаем по score, а не теряем всё.
        if len(result) > self.max_chunk_hits:
            result.sort(key=lambda x: -x[1])
            return result[:self.max_chunk_hits]
        return result

    def verify_param(self, name, initial_score, initial_reasons):
        canary = rand_canary()
        results = []
        for _ in range(7):
            m, u, h, b = build_request(self.base_req, {name: canary}, self.mode)
            r = self._request(m, u, h, b, timeout=self.timeout, proxy=self.proxy)
            if r.error: continue
            sev, _, _ = detect_rate_limit(r)
            if sev >= 2: continue
            results.append(r)
        if not results: return None

        d_scores = [diff_oracle(r, self.calib, self.exclude_error_statuses)
                    for r in results]
        d_hits = sum(1 for s, _ in d_scores if s > 0)
        # TTFB-based time-oracle: убирает шум от размера ответа
        probe_times = [r.ttfb if r.ttfb > 0 else r.elapsed for r in results]
        t_score, t_reason = time_oracle_ttest(probe_times, self.calib,
                                              self.p_value_threshold)
        f_score, f_reason, contexts = reflection_oracle(results[0], [canary])
        # NEW: отдельный header-reflection oracle (Location/Set-Cookie/...)
        hr_score, hr_reason = header_reflection_oracle(results[0], [canary])
        cache_score, cache_reason = (cache_key_oracle(results[0], self.calib)
                                     if self.use_cache_oracle else (0.0, None))
        # NEW v0.5.2: server-timing + cookie oracles
        st_score, st_reason = server_timing_oracle(results[0], self.calib)
        ck_score, ck_reason = cookie_oracle(results[0], self.calib)

        signals = []
        if d_hits >= 4: signals.append(max(d_scores, key=lambda x: x[0]))
        if t_score > 0: signals.append((t_score, t_reason))
        if f_score > 0: signals.append((f_score, f_reason))
        if hr_score > 0: signals.append((hr_score, hr_reason))
        if cache_score > 0: signals.append((cache_score, cache_reason))
        if st_score > 0: signals.append((st_score, st_reason))
        if ck_score > 0: signals.append((ck_score, ck_reason))

        # requester, который ходит через governor (rate-limit) этого сканера —
        # чтобы новые активные оракулы тоже соблюдали --max-rps.
        def _req(m, u, h, b):
            return self._request(m, u, h, b, timeout=self.timeout,
                                 proxy=self.proxy)

        # отныне наварил boolean-pair oracle — стабильное расхождение противоположных
        # значений. Сильный антишумовой сигнал. Гоняем в direct-probe всегда,
        # иначе — как подтверждение когда есть лишь слабые сигналы.
        weak_only = signals and all(s < 0.55 for s, _ in signals)
        if (self.direct_probe or not signals or weak_only) \
                and not self.skip_error_oracle:
            try:
                bp = boolean_pair_oracle(self.base_req, name, self.mode,
                                         self.proxy, self.timeout, requester=_req)
                if bp[0] > 0: signals.append(bp)
            except Exception: pass

            # теперь тут parameter-pollution oracle (дубль ключа)
            try:
                pp = pollution_oracle(self.base_req, name, self.mode,
                                      self.proxy, self.timeout, self.calib,
                                      requester=_req)
                if pp[0] > 0: signals.append(pp)
            except Exception: pass

        # даже если классические оракулы не сработали,
        # запускаем semantic probe — он может детектить параметры на
        # CDN-кэшированных целях через distinct response signatures.
        # В direct-probe режиме запускаем ВСЕГДА (это основной оракул там),
        # иначе — только если других сигналов нет (экономия запросов).
        if (self.direct_probe or not signals) and not self.skip_error_oracle:
            try:
                sp = semantic_probe_oracle(self.base_req, name, self.mode,
                                            self.proxy, self.timeout,
                                            self.governor)
                if sp[0] > 0: signals.append(sp)
            except Exception: pass

        if not signals: return None

        if not self.skip_error_oracle:
            try:
                e = error_oracle(self.base_req, name, self.mode,
                                 self.proxy, self.timeout, self.governor)
                if e[0] > 0: signals.append(e)
            except Exception: pass

        # DOM-oracle: heavy (запускает Chromium), поэтому вызываем только если
        # включён и хотя бы один лёгкий сигнал уже есть. Это работает как
        # доп. подтверждение для борьбы с false positives, особенно для SPA.
        if self.use_dom_oracle:
            # Lazy-init оттуда: Playwright sync API thread-affinity.
            # max_workers=1 в run() гарантирует, что все verify_param идут отсюда.
            self._init_dom_oracle()
        if self.use_dom_oracle and self.dom_scanner and self.dom_baseline:
            try:
                dom_canary = rand_canary()
                d_score, d_reason = dom_diff_oracle(
                    self.base_req['url'], name, dom_canary, self.mode,
                    self.dom_scanner, self.dom_baseline)
                if d_score > 0: signals.append((d_score, d_reason))
            except Exception as ex:
                # DOM-oracle нестабилен — браузер может крашнуться на одной странице,
                # но работать на других. Логируем, но не отключаем oracle.
                self._log(f'[!] DOM-oracle error for {name}: {ex}', 'warn')

        total, reasons = aggregate(*signals)
        if total < self.confidence_threshold: return None
        # теперь тут anti-false-positive gate. Несколько слабых сигналов (timing-шум +
        # redirect-echo) перемножаются в высокий total через aggregate(), но это
        # ничего не значит. Требуем хотя бы ОДИН самостоятельно убедительный
        # сигнал. Иначе — отбрасываем (это и убивало те 12 фантомных 0.78, что были раннее)
    
        if not any(s >= 0.55 for s, _ in signals):
            return None

        pivot_urls = set()
        if self.enable_pivot:
            new_urls = extract_pivot_urls(results[0].text, canary,
                                           self.base_req['url'])
            pivot_urls.update(new_urls)

        return Finding(name, total, reasons, contexts=contexts,
                       pivot_urls=pivot_urls, endpoint=self.base_req['url'])

    def run(self, wordlist):
        self.calibrate()

        if self.direct_probe:
            return self._run_direct_probe(wordlist)
        if self.stream_verify:
            return self._run_streaming(wordlist)
        return self._run_batched(wordlist)

    def _run_direct_probe(self, wordlist):
  
        # Дедуп входного словаря с сохранением порядка
        seen = set(); uniq_words = []
        for w in wordlist:
            if w not in seen:
                seen.add(w); uniq_words.append(w)

        self._log(f'[*] DIRECT-PROBE mode: {len(uniq_words)} params, each probed '
                  f'individually with full oracle stack (semantic_probe forced). '
                  f'threads={self.adaptive_threads}, '
                  f'dom-oracle={"on" if self.use_dom_oracle else "off"}')
        self._log('[*] This is slow (~13-18 req/param). Use a focused wordlist '
                  'or leave it running.')

        if self.printer:
            self.printer.update_progress(stage='verify',
                                         verify_total=len(uniq_words),
                                         verified_done=0)

        verified = [0]
        # DOM-oracle (Playwright sync) thread-affinity → один поток при включённом.
        workers = 1 if self.use_dom_oracle else max(self.adaptive_threads, 1)

        def probe_one(name):
            try:
                # initial_score/reasons не нужны в этом режиме — verify_param
                # сам решает по оракулам. Передаём 0.0 / [] как заглушки.
                return self.verify_param(name, 0.0, [])
            except Exception as e:
                self._log(f'[!] probe error for {name!r}: {e}', 'warn')
                return None

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(probe_one, n): n for n in uniq_words}
            for fut in as_completed(futures):
                with self.lock:
                    verified[0] += 1
                    if self.printer:
                        self.printer.update_progress(verified_done=verified[0])
                res = fut.result()
                if res:
                    with self.lock:
                        self.findings.append(res)
                        if self.printer:
                            self.printer.emit_finding(res)

        if self.governor and self.governor.total_rate_limits > 0:
            self._log(f'[*] Rate-limits total: {self.governor.total_rate_limits}')

        self._dom_oracle_cleanup()
        return self.findings

    def _run_streaming(self, wordlist):
        
        cs = min(self.chunk_size, max(5, len(wordlist) // 4))
        chunks = [wordlist[i:i + cs] for i in range(0, len(wordlist), cs)]
        self._log(f'[*] Streaming scan: {len(wordlist)} params in {len(chunks)} chunks '
                  f'(size={cs}, threads={self.adaptive_threads}, '
                  f'verify=concurrent, dom-oracle={"on" if self.use_dom_oracle else "off"})')

        if self.printer:
            self.printer.update_progress(stage='scan', total_chunks=len(chunks),
                                         chunks_done=0, cands_found=0,
                                         verify_total=0, verified_done=0)

        # Verify-queue: tuple (priority_neg_score, candidate_id, name, score, reasons)
        # priority_neg_score нужен для PriorityQueue: сначала высокий score
        # (мы используем -score чтобы max-heap эмулировать через min-heap)
        verify_q = queue.PriorityQueue()
        # Счётчик чтобы сделать tuple-priority стабильным (избежать сравнения
        # reasons при равных score, что упадёт на list of dicts):
        cand_counter = [0]

        # Состояние pipeline
        discovery_done = threading.Event()
        verify_stats = {'queued': 0, 'verified': 0, 'dropped_cap': 0, 'dropped_dup': 0}
        stats_lock = threading.Lock()

        def push_candidate(name, score, reasons):
            """Кладёт кандидата в очередь с защитой от cap и dup."""
            # Дедупликация
            with self._stream_seen_lock:
                if name in self._stream_seen:
                    with stats_lock: verify_stats['dropped_dup'] += 1
                    return
                self._stream_seen.add(name)

            # Cap: если очередь переполнена, отбрасываем низкоприоритетных
            with stats_lock:
                qsize = verify_q.qsize()
                if qsize >= self.stream_verify_cap:
                    # Если новый кандидат значимо лучше худшего в очереди — заменим.
                    # Иначе просто drop. PriorityQueue не даёт нам легко посмотреть
                    # худший, поэтому используем простой эвристический cap.
                    verify_stats['dropped_cap'] += 1
                    return
                cand_counter[0] += 1
                cid = cand_counter[0]
                verify_stats['queued'] += 1

            verify_q.put((-score, cid, name, score, reasons))
            if self.printer:
                self.printer.update_progress(verify_total=verify_stats['queued'])

        # Discovery worker — кладёт кандидатов в очередь
        progress = [0]
        def discovery_worker(chunk):
            try:
                hits = self.test_chunk(chunk)
                with self.lock:
                    progress[0] += 1
                    if self.printer:
                        self.printer.update_progress(
                            chunks_done=progress[0],
                            cands_found=verify_stats['queued'])

                if self.stream_candidates and hits and self.printer:
                    for name, score, reasons in hits:
                        self.printer.emit_candidate(
                            name, score, reasons, self.base_req['url'])

                # Главное: кладём в verify-очередь сразу
                for name, score, reasons in hits:
                    push_candidate(name, score, reasons)
                return hits
            except Exception as e:
                self._log(f'[!] chunk error: {e}', 'warn'); return []

        # Verify worker — один поток, чтобы Playwright (DOM-oracle) был happy
        def verify_worker():
            while True:
                try:
                    item = verify_q.get(timeout=0.5)
                except queue.Empty:
                    if discovery_done.is_set():
                        break  # discovery закончен и очередь пуста
                    continue

                _neg_score, _cid, name, score, reasons = item
                try:
                    result = self.verify_param(name, score, reasons)
                    with stats_lock:
                        verify_stats['verified'] += 1
                    if self.printer:
                        self.printer.update_progress(
                            verified_done=verify_stats['verified'])
                    if result:
                        with self.lock:
                            self.findings.append(result)
                            if self.printer:
                                self.printer.emit_finding(result)
                except Exception as e:
                    self._log(f'[!] verify error for {name}: {e}', 'warn')
                finally:
                    verify_q.task_done()

        # Запускаем verify-worker заранее (даже если очередь пуста, он ждёт)
        verify_thread = threading.Thread(target=verify_worker, daemon=True,
                                          name='verify-worker')
        verify_thread.start()

        # Discovery — ThreadPool как раньше
        max_workers = max(self.adaptive_threads * 2, 4)
        try:
            with ThreadPoolExecutor(max_workers=max_workers,
                                     thread_name_prefix='discovery') as ex:
                list(as_completed([ex.submit(discovery_worker, c) for c in chunks]))
        finally:
            # Сигнал verify-worker'у: discovery закончен, добей очередь и выходи
            discovery_done.set()

        self._log(f'[*] Discovery done: {verify_stats["queued"]} candidates queued, '
                  f'{verify_stats["dropped_dup"]} dup, '
                  f'{verify_stats["dropped_cap"]} dropped (cap)')
        self._log(f'[*] Waiting for verify to finish '
                  f'({verify_stats["queued"] - verify_stats["verified"]} remaining)...')

        # Ждём окончания verify
        verify_thread.join()

        if self.governor and self.governor.total_rate_limits > 0:
            self._log(f'[*] Rate-limits total: {self.governor.total_rate_limits}')

        self._dom_oracle_cleanup()
        return self.findings

    def _run_batched(self, wordlist):
        """Классический batch-режим: сначала весь discovery, потом весь verify."""
        cs = min(self.chunk_size, max(5, len(wordlist) // 4))
        chunks = [wordlist[i:i + cs] for i in range(0, len(wordlist), cs)]
        self._log(f'[*] Scanning {len(wordlist)} params in {len(chunks)} chunks '
                  f'(size={cs}, threads={self.adaptive_threads}, '
                  f'rl-adapt={"on" if self.rate_limit_adapt else "off"})...')

        if self.printer:
            self.printer.update_progress(stage='scan', total_chunks=len(chunks),
                                         chunks_done=0, cands_found=0)

        candidates = []
        progress = [0]
        def worker(chunk):
            try:
                hits = self.test_chunk(chunk)
                with self.lock:
                    progress[0] += 1
                    candidates.extend(hits)
                    if self.printer:
                        self.printer.update_progress(
                            chunks_done=progress[0], cands_found=len(candidates))
                # Стрим кандидатов (вне self.lock — emit использует свой lock)
                if self.stream_candidates and hits and self.printer:
                    for name, score, reasons in hits:
                        self.printer.emit_candidate(
                            name, score, reasons, self.base_req['url'])
                return hits
            except Exception as e:
                self._log(f'[!] chunk error: {e}', 'warn'); return []

        max_workers = max(self.adaptive_threads * 2, 4)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            list(as_completed([ex.submit(worker, c) for c in chunks]))

        self._log(f'[*] Stage 1: {len(candidates)} candidates')
        if self.governor and self.governor.total_rate_limits > 0:
            self._log(f'[*] Rate-limits during scan: '
                      f'{self.governor.total_rate_limits}')

        seen = set(); uniq = []
        for n, s, r in candidates:
            if n not in seen: seen.add(n); uniq.append((n, s, r))

        MAX_VERIFY = 200
        if len(uniq) > MAX_VERIFY:
            self._log(f'[!] {len(uniq)} > {MAX_VERIFY}, taking top by confidence',
                      'warn')
            uniq.sort(key=lambda x: -x[1]); uniq = uniq[:MAX_VERIFY]

        if not self.verify:
            for n, s, r in uniq:
                f = Finding(n, s, r, endpoint=self.base_req['url'])
                self.findings.append(f)
                if self.printer: self.printer.emit_finding(f)
            self._dom_oracle_cleanup()
            return self.findings

        self._log(f'[*] Verifying {len(uniq)} unique candidates...')
        if self.printer:
            self.printer.update_progress(stage='verify', verify_total=len(uniq),
                                         verified_done=0)

        verified = [0]
        # DOM-oracle нельзя гонять из нескольких потоков — Playwright sync API
        # привязан к треду, где был запущен. При use_dom_oracle делаем verify
        # однопоточным. Хотя в целом похуй, DOM-snapshot сам по себе медленный.
        verify_workers = 1 if self.use_dom_oracle else 2
        with ThreadPoolExecutor(max_workers=verify_workers) as ex:
            futures = {ex.submit(self.verify_param, n, s, r): n
                       for n, s, r in uniq}
            for f in as_completed(futures):
                with self.lock:
                    verified[0] += 1
                    if self.printer:
                        self.printer.update_progress(verified_done=verified[0])
                res = f.result()
                if res:
                    with self.lock:
                        self.findings.append(res)
                        if self.printer: self.printer.emit_finding(res)
        # Освобождаем Chromium ресурсы (если использовали DOM-oracle)
        self._dom_oracle_cleanup()
        return self.findings


# ============================================================================
#  PIVOT ORCHESTRATOR
# ============================================================================

def run_with_pivot(base_req, wordlist, scan_kwargs, pivot_depth=1,
                   max_pivot_endpoints=10, printer=None):
    all_findings = []
    queue = deque([(base_req['url'], 0)])
    visited = set([base_req['url'].rstrip('/').split('?')[0]])
    pivots_scanned = 0

    while queue:
        url, depth = queue.popleft()
        if depth > pivot_depth: continue
        if pivots_scanned >= max_pivot_endpoints:
            (printer.emit_log if printer else log)(
                f'[!] Pivot limit reached ({max_pivot_endpoints})', 'warn')
            break

        cur_req = dict(base_req); cur_req['url'] = url
        msg = f'\n[*] {"PIVOT" if depth > 0 else "INITIAL"} scan: {url} (depth={depth})'
        if printer: printer.emit_log(msg)
        else: log(msg)

        scanner = Scanner(base_req=cur_req, printer=printer, **scan_kwargs)
        findings = scanner.run(wordlist)

        for f in findings:
            all_findings.append(f)
            if f.pivot_urls and depth < pivot_depth:
                for purl in f.pivot_urls:
                    norm = purl.rstrip('/').split('?')[0]
                    if norm not in visited:
                        visited.add(norm)
                        queue.append((purl, depth + 1))
                        m = f'    [+] PIVOT discovered: {f.name!r} -> {purl}'
                        if printer: printer.emit_log(m)
                        else: log(m)

        if depth > 0: pivots_scanned += 1
    return all_findings


# ============================================================================
#  REQUEST FILE PARSING
# ============================================================================

def parse_request_file(path, default_scheme='https'):
    with open(path, 'rb') as f: raw = f.read()
    try: text = raw.decode('utf-8')
    except UnicodeDecodeError: text = raw.decode('latin-1')
    if '\r\n\r\n' in text: head, body = text.split('\r\n\r\n', 1)
    elif '\n\n' in text: head, body = text.split('\n\n', 1)
    else: head, body = text, ''
    lines = head.replace('\r\n', '\n').split('\n')
    if not lines: die('empty request file')
    parts = lines[0].split(' ')
    if len(parts) < 2: die('malformed request line')
    method, path_ = parts[0], parts[1]
    headers = {}
    for ln in lines[1:]:
        if ':' in ln:
            k, v = ln.split(':', 1); headers[k.strip()] = v.strip()
    host = headers.get('Host') or headers.get('host')
    if not host: die('Host header missing')
    return {'method': method, 'url': f'{default_scheme}://{host}{path_}',
            'headers': headers,
            'body': body.encode('utf-8') if body else None}


# ============================================================================
#  CLI
# ============================================================================

def log(msg): sys.stderr.write(msg + '\n'); sys.stderr.flush()
def die(msg, code=1): log(f'[FATAL] {msg}'); sys.exit(code)

def load_wordlist(path):
    if path == '-':
        return [w.strip() for w in sys.stdin if w.strip() and not w.startswith('#')]
    if not os.path.isfile(path): die(f'wordlist not found: {path}')
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return [w.strip() for w in f if w.strip() and not w.startswith('#')]


HELP_RU = """
==============================================================================
 paraminer — РУКОВОДСТВО ПО ИСПОЛЬЗОВАНИЮ
==============================================================================

ЧТО ДЕЛАЕТ
----------
Ищет скрытые HTTP-параметры (query, body, headers, JSON), которые обрабатывает
бэкенд, но которых нет во фронтенде. Использует 5 независимых оракулов для
детекции (+ опциональный DOM-diff oracle через playwright) и Welch's t-test
для статистической достоверности.

БЫСТРЫЙ СТАРТ
-------------
  python3 paraminer.py -u https://target.com/api/users -w wordlist.txt
  python3 paraminer.py -u https://target.com/ -w wordlist.txt --pivot
  python3 paraminer.py --selftest

ОСНОВНЫЕ ФЛАГИ
--------------
  -u, --url URL
        Целевой URL. Пример: -u "https://target.com/api/v1/users"

  -r, --request FILE
        Raw HTTP request (как из Burp). Альтернатива -u, поддерживает
        кастомные методы/заголовки/тело.

  -w, --wordlist FILE
        Файл со списком параметров (по строке на параметр). '-' = stdin.

  -X, --method METHOD       HTTP метод (GET по умолчанию)
  -H, --header "Name: val"  Доп. заголовок (повторяется)
  -d, --data STRING         Тело запроса
  -b, --cookie STRING       Cookie header

РЕЖИМ ИНЪЕКЦИИ (куда подставлять параметры)
-------------------------------------------
  --mode {query,form,json,headers}   Явно указать режим
  --json     Шорткат для --mode json (для API)
  --form     Шорткат для --mode form (form-urlencoded)
  --headers  Шорткат для --mode headers (фаззинг HTTP-заголовков!)

  Если не указано, режим выбирается автоматически по методу и Content-Type.

ПРОИЗВОДИТЕЛЬНОСТЬ
------------------
  -c, --threads N           Потоков (default 4). Не больше 8 на серьёзный
                            сайт — поймаешь rate-limit мгновенно.
  -m, --chunk-size N        Параметров в одном пробном запросе (default 25).
                            Меньше = точнее но медленнее, больше = быстрее
                            но больше false positives.
  -n, --calibration N       Baseline-запросов до скана (default 10).
  -t, --timeout SEC         Timeout одного запроса (default 15s).

ТЮНИНГ ОРАКУЛОВ
---------------
  --confidence FLOAT        Минимальный confidence для report (0..1, def 0.5).
                            Выше = меньше шума, ниже = ловишь больше слабых.
  --p-value FLOAT           p-value для t-test time-oracle (default 0.001).
                            Меньше = строже к латенси.
  --time-threshold FLOAT    MAD threshold для time (default 4.0, легаси).

ФИЛЬТРЫ ШУМА
------------
  --max-chunk-hits N        Если из чанка вылезло >N кандидатов — чанк шумит,
                            выкидываем целиком (default 8). На WAF-сайтах
                            используй 3-4.
  --exclude-error-statuses  Не репортить параметры, дающие только 4xx/5xx.
                            ВАЖНО для WordPress-целей: убирает шум типа
                            ?feed=, ?attachment= и т.п.
  --skip-error-oracle       Пропустить error-oracle (быстрее verify в 6 раз).
  --no-cache-oracle         Отключить cache-key oracle.
  --no-verify               Только stage 1, без верификации. Очень быстро,
                            но много FP.

DOM-ORACLE (browser-based, для SPA)
-----------------------------------
  --dom-oracle              Включить DOM-diff oracle. Запускает headless
                            Chromium через playwright, делает baseline-snapshot
                            страницы (DOM + XHR + cookies + localStorage), потом
                            для каждого кандидата сравнивает с baseline.
  --dom-timeout SEC         Timeout для одного DOM-snapshot (default 20s).

  Когда использовать:
    • SPA на React/Vue/Angular — обычные diff/reflection оракулы не видят
      параметры, которые меняют только client-side render.
    • Сайты с heavy JS, где ответ HTTP минимален, но JS на основании
      query-параметров меняет страницу.
    • Когда нужна доп. верификация против false positives на динамических
      страницах (timestamps, CSRF-токены).

  Ограничения:
    • Работает только с mode=query (для headers/body DOM-diff не имеет смысла).
    • Требует: pip install playwright && playwright install chromium (~300MB).
    • Медленный: каждый DOM-snapshot 1-3 сек + verify становится однопоточным
      (Playwright sync API thread-affinity). На 50 кандидатах добавляет ~1-2 мин.
    • Если playwright не установлен или snapshot baseline не удался —
      oracle тихо отключается, остальной скан продолжается.

RATE LIMIT / WAF
----------------
  --no-rate-limit-adapt     Отключить авто-замедление на 429/CF.
                            По умолчанию ВКЛЮЧЕНО.

  Параметры адаптации НЕ настраиваются вручную — governor сам решает по
  3 уровням: SOFT (>5% rl), HARD (>20% rl), CRITICAL (WAF challenge / 5+ 429).
  После rate-limit'а скорость НЕ возвращается к исходной (sticky degradation).

PIVOT (рекурсивный скан найденных URL'ов)
-----------------------------------------
  --pivot                   Включить auto-pivot.
  --pivot-depth N           Глубина рекурсии (default 1). 0 = только initial.
  --pivot-max N             Макс кол-во pivot-endpoints (default 10).

  Что это: когда канарейка попадает в URL (href, src, og:url, location.href),
  сканер автоматически добавляет этот URL в очередь и сканирует его тем же
  wordlist'ом. Same-origin only.

PRE-FLIGHT CHECK (v0.5)
-----------------------
  По умолчанию paraminer ВСЕГДА делает быструю диагностику target'а перед
  скан-фазой (6-12 запросов). Определяет:
    • CDN/cache (Cloudflare, Fastly, Akamai, CloudFront, Varnish)
    • WAF (CF challenge, AWS WAF, Akamai, Imperva)
    • OAuth strict-validation
    • Reactive params (отвечает ли вообще на параметры)

  Если target определён как «non-reactive» — paraminer ОСТАНОВИТСЯ
  с объяснением. Используй --force-scan чтобы пропустить эту проверку.

  --no-preflight            Пропустить pre-flight полностью
  --force-scan              Игнорировать вердикт pre-flight (сканить всё равно)

ПРОКСИ / СЕТЬ
-------------
  --proxy URL               HTTP-прокси (например http://127.0.0.1:8080 для Burp)

ВЫВОД
-----
  -o, --output FILE         Сохранить findings в JSON
  --no-color                Отключить ANSI (auto в pipe/non-TTY)

  Каждая находка печатается СРАЗУ при подтверждении (streaming, как в x8).

ДРУГОЕ
------
  --selftest                Встроенные тесты (поднимает локальные серверы)

==============================================================================
 РЕКОМЕНДАЦИИ ПО ФАЗЗИНГУ
==============================================================================

КАК ВЫБИРАТЬ ЦЕЛЬ
-----------------
Хорошие цели для скана:
  ✓ API endpoints (/api/users, /api/v1/products)
  ✓ Поисковые формы (/search, /query)
  ✓ Страницы с фильтрами/сортировкой (/products?sort=...)
  ✓ Admin/staff endpoints (если есть креды)
  ✓ Эндпоинты "конфигурации" (/settings, /profile)

ПЛОХИЕ цели (зря потратишь время):
  ✗ OAuth/SSO/login страницы (strict validation)
  ✗ Статические лендинги под CDN-кэшем
  ✗ Эндпоинты с CSRF-tokens, требующие сессию (без -b cookies)
  ✗ Эндпоинты, возвращающие 302 redirect на всё подряд

PRE-FLIGHT тебе это подскажет.

ПОДГОТОВКА WORDLIST'А
---------------------
  Маленький wordlist (1-5k) — для быстрых прогонов или Termux:
    https://github.com/s0md3v/Arjun/blob/master/arjun/db/params.txt

  Большой wordlist (50k+) — для нормальных программ:
    https://github.com/PortSwigger/param-miner

  Tech-specific wordlists работают лучше generic'ов. Если знаешь
  что target на WordPress — добавь WP-specific params (preview, p, cat,
  rest_route, replytocom). Laravel/Symfony — свои (_token, _method).

ТЮНИНГ ПОД ЦЕЛЬ
---------------
  Target агрессивный (CF, AWS WAF, rate-limit):
    -c 2 -m 10 --max-chunk-hits 3 --exclude-error-statuses --skip-error-oracle

  Target стабильный, хочешь всё:
    -c 4 -m 25 --confidence 0.4 --pivot --pivot-depth 1

  Маленький endpoint API:
    -c 4 -m 15 --json --confidence 0.45 --skip-error-oracle

  Termux на мобильном:
    -c 2 -m 20 --no-color --skip-error-oracle

  Спать на ночь, сканить долго:
    -c 6 -m 25 --pivot --pivot-depth 2 -o results.json

ИНТЕРПРЕТАЦИЯ РЕЗУЛЬТАТОВ
-------------------------
  [1.00] — статус-код изменился (404/302/500). Часто роутер/WAF, проверь вручную.
  [0.95] — рефлексия канарейки В body или сильный diff.
  [0.85-0.94] — несколько оракулов сошлись. Скорее всего реальный параметр.
  [0.60-0.84] — один сильный сигнал. Проверь ручкой.
  [0.50-0.59] — слабые сигналы. Часто FP, но иногда скрытый rate-limited param.

  Context-classifier подсказывает класс уязвимости:
    html_text → попробуй XSS: <svg/onload=alert(1)>
    url_path / href_attr → Open Redirect: ?param=//evil.com
    js_string_double → XSS через ": ?param=";alert(1);//
    meta_url_canonical → canonical poisoning / OG-scraper SSRF

"""
      
def main():
    
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        # Python < 3.7 или экзотический stdout — fallback
        os.environ['PYTHONUNBUFFERED'] = '1'

    # Кастомный help — печатаем сами при --help-ru или -hr
    if '--help-ru' in sys.argv or '-hr' in sys.argv:
        print(HELP_RU); sys.exit(0)

    ap = argparse.ArgumentParser(
        prog='paraminer.py',
        description='paraminer v0.5 — multi-oracle hidden parameter discovery. '
                    'Используй --help-ru для подробной справки на русском.',
        epilog='Examples:\n'
               '  %(prog)s -u https://target.com/api -w params.txt\n'
               '  %(prog)s -u https://target.com/ -w params.txt --pivot\n'
               '  %(prog)s --selftest\n'
               '  %(prog)s --help-ru    (подробная справка с рекомендациями)',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    ap.add_argument('--help-ru', '-hr', action='store_true',
                    help='подробная справка на русском')
    ap.add_argument('--selftest', action='store_true',
                    help='встроенные тесты (поднимает локальные серверы)')
    g = ap.add_mutually_exclusive_group()
    g.add_argument('-u', '--url', help='target URL')
    g.add_argument('-r', '--request', help='raw HTTP request file (Burp-style)')

    ap.add_argument('-w', '--wordlist', help='файл со словарём параметров (или -)')
    ap.add_argument('-X', '--method', default='GET', help='HTTP method')
    ap.add_argument('-H', '--header', action='append', default=[],
                    help='доп. заголовок "Name: value" (повторяется)')
    ap.add_argument('-d', '--data', help='тело запроса')
    ap.add_argument('-b', '--cookie', help='Cookie header value')

    ap.add_argument('--mode', choices=['query', 'form', 'json', 'headers'],
                    help='режим инъекции (auto если не указан)')
    ap.add_argument('--json', action='store_true', help='шорткат --mode json')
    ap.add_argument('--form', action='store_true', help='шорткат --mode form')
    ap.add_argument('--headers', action='store_true',
                    help='шорткат --mode headers (фаззинг HTTP-заголовков)')

    ap.add_argument('-c', '--threads', type=int, default=4,
                    help='потоков (default 4, max 8 рекомендуется)')
    ap.add_argument('-m', '--chunk-size', type=int, default=25,
                    help='параметров в одном запросе (default 25)')
    ap.add_argument('-n', '--calibration', type=int, default=10,
                    help='baseline-запросов (default 10)')
    ap.add_argument('-t', '--timeout', type=int, default=15,
                    help='timeout запроса в сек (default 15)')

    ap.add_argument('--time-threshold', type=float, default=4.0,
                    help='MAD-threshold для time-oracle (default 4.0)')
    ap.add_argument('--p-value', type=float, default=0.001,
                    help='p-value для Welch t-test (default 0.001)')
    ap.add_argument('--confidence', type=float, default=0.5,
                    help='минимальный confidence (default 0.5)')

    ap.add_argument('--no-verify', action='store_true',
                    help='пропустить verify-стадию (быстро, но шумно)')
    ap.add_argument('--max-chunk-hits', type=int, default=8,
                    help='макс кандидатов из чанка (default 8)')
    ap.add_argument('--exclude-error-statuses', action='store_true',
                    help='не репортить параметры с 4xx/5xx (для WP/Drupal)')
    ap.add_argument('--skip-error-oracle', action='store_true',
                    help='пропустить error-oracle (быстрее verify в 6x)')
    ap.add_argument('--no-cache-oracle', action='store_true',
                    help='отключить cache-key oracle')
    ap.add_argument('--dom-oracle', action='store_true',
                    help='включить DOM-diff oracle (требует playwright + chromium; '
                         'медленнее, но детектит SPA-параметры)')
    ap.add_argument('--dom-timeout', type=int, default=20,
                    help='timeout для DOM-snapshot в секундах (default 20)')

    ap.add_argument('--pivot', action='store_true',
                    help='auto-pivot: scan URL найденные в reflections')
    ap.add_argument('--pivot-depth', type=int, default=1,
                    help='глубина pivot (default 1)')
    ap.add_argument('--pivot-max', type=int, default=10,
                    help='макс pivot-endpoints (default 10)')

    ap.add_argument('--no-rate-limit-adapt', action='store_true',
                    help='отключить авто-адаптацию на rate-limit (default ON)')
    ap.add_argument('--no-preflight', action='store_true',
                    help='пропустить pre-flight check')
    ap.add_argument('--force-scan', action='store_true',
                    help='игнорировать вердикт pre-flight и сканить всё равно')
    ap.add_argument('--stream-candidates', action='store_true',
                    help='[DEPRECATED, no-op] стрим кандидатов теперь включён '
                         'по умолчанию. Флаг оставлен для совместимости.')
    ap.add_argument('--no-stream-candidates', action='store_true',
                    help='отключить стрим кандидатов из stage 1 '
                         '(только подтверждённые findings будут показаны)')
    ap.add_argument('--stream-verify', action='store_true',
                    help='verify каждого кандидата СРАЗУ как только найден '
                         '(вместо ожидания окончания stage 1). Параллельно с '
                         'discovery идёт verify-pipeline через очередь. '
                         'Особенно полезно на больших wordlist (50k+), когда '
                         'stage 1 занимает часы — реальные findings всплывают '
                         'через первые минуты, а не в конце.')
    ap.add_argument('--stream-verify-cap', type=int, default=500,
                    help='максимум кандидатов в очереди stream-verify (default 500). '
                         'Защита от echo-таргетов: если discovery нашёл больше, '
                         'низкоприоритетные отбрасываются по score.')
    ap.add_argument('--direct-probe', action='store_true',
                    help='Режим для CDN/non-reactive таргетов. Полностью обходит '
                         'chunk-based discovery и гоняет полный verify (включая '
                         'принудительный semantic_probe по distinct response-'
                         'signatures) по КАЖДОМУ параметру напрямую. Работает там, '
                         'где diff бесполезен (кэшированный HTML, params не доходят '
                         'до бэкенда заметно для diff). Медленный (~13-18 req/param): '
                         'используй с сокращённым/таргетированным словарём.')

    ap.add_argument('--proxy', help='HTTP proxy URL (e.g. для Burp)')
    ap.add_argument('--max-rps', type=float, default=5.0,
                    help='глобальный лимит запросов в секунду по всем потокам '
                         '(default 5.0 — лимит правил Standoff365/YooMoney). '
                         '0 = без ограничения. Применяется ко всем запросам '
                         '(калибровка, preflight, все оракулы).')
    ap.add_argument('-o', '--output', help='сохранить findings в JSON')
    ap.add_argument('--no-color', action='store_true', help='отключить ANSI')
    args = ap.parse_args()

    auto_color_setup(force_disable=args.no_color)

    # Глобальный rate-limit (по умолчанию 5 rps).
    RATE_LIMITER.configure(args.max_rps)
    if args.max_rps and args.max_rps > 0:
        log(f'[*] Global rate limit: {args.max_rps:g} req/s (all threads)')

    if args.selftest:
        sys.exit(run_selftest())

    if not (args.url or args.request):
        die('требуется -u/--url или -r/--request (или --selftest, --help-ru)')
    if not args.wordlist: die('требуется -w/--wordlist')

    if args.request:
        base = parse_request_file(args.request)
    else:
        headers = {}
        for hh in args.header:
            if ':' in hh:
                k, v = hh.split(':', 1); headers[k.strip()] = v.strip()
        if args.cookie: headers['Cookie'] = args.cookie
        base = {'method': args.method.upper(), 'url': args.url,
                'headers': headers,
                'body': args.data.encode('utf-8') if args.data else None}

    mode = args.mode
    if args.json: mode = 'json'
    elif args.form: mode = 'form'
    elif args.headers: mode = 'headers'
    if not mode:
        if base['method'] in ('POST', 'PUT', 'PATCH'):
            ct = (base['headers'].get('Content-Type')
                  or base['headers'].get('content-type', '')).lower()
            mode = 'json' if 'json' in ct else 'form'
        else: mode = 'query'

    log(f'[*] Inject mode: {mode}'
        + (' [+pivot]' if args.pivot else '')
        + (' [+rl-adapt]' if not args.no_rate_limit_adapt else ''))

    # Валидация совместимости --dom-oracle с другими опциями
    if args.dom_oracle:
        if mode != 'query':
            log(f'[!] --dom-oracle: works only with mode=query, '
                f'got mode={mode}. DOM-oracle will be disabled.')
            args.dom_oracle = False
        elif not _check_playwright():
            log('[!] --dom-oracle: playwright not installed. Install via:')
            log('      pip install playwright && playwright install chromium')
            log('    DOM-oracle will be disabled.')
            args.dom_oracle = False
        else:
            log('[*] DOM-oracle enabled (slower, but catches SPA params)')

    printer = StreamPrinter(quiet=False)

    # --- Pre-flight ---
    if not args.no_preflight:
        report, _ = preflight_check(base, mode, timeout=args.timeout,
                                     proxy=args.proxy, printer=printer)
        for line in report.summary():
            printer.emit_log(f'    {line}')

        if report.is_non_reactive and not args.force_scan and not args.direct_probe:
            printer.emit_log('\n[!] Target appears NON-REACTIVE.', 'warn')
            for rec in report.recommendations:
                printer.emit_log(f'    {rec}', 'warn')
            printer.emit_log('    TRY: --direct-probe (per-param semantic probing, '
                             'works through CDN cache)', 'warn')
            printer.emit_log('\nAborting. Use --direct-probe or --force-scan to '
                             'override.', 'err')
            sys.exit(2)
        elif report.is_non_reactive and args.direct_probe:
            printer.emit_log('[!] Non-reactive target, but --direct-probe: '
                             'proceeding with per-param semantic probing', 'warn')
        elif report.is_non_reactive:
            printer.emit_log('[!] Non-reactive, but --force-scan: proceeding',
                             'warn')

    wordlist = load_wordlist(args.wordlist)
    if not wordlist: die('empty wordlist')
    log(f'[*] Loaded {len(wordlist)} candidate params')

    scan_kwargs = dict(
        mode=mode, proxy=args.proxy, timeout=args.timeout,
        chunk_size=args.chunk_size, threads=args.threads,
        calibration_n=args.calibration, confidence_threshold=args.confidence,
        verify=not args.no_verify, time_threshold_mads=args.time_threshold,
        max_chunk_hits=args.max_chunk_hits,
        exclude_error_statuses=args.exclude_error_statuses,
        skip_error_oracle=args.skip_error_oracle,
        p_value_threshold=args.p_value,
        use_cache_oracle=not args.no_cache_oracle,
        enable_pivot=args.pivot,
        rate_limit_adapt=not args.no_rate_limit_adapt,
        stream_candidates=not args.no_stream_candidates,
        use_dom_oracle=args.dom_oracle,
        dom_timeout=args.dom_timeout,
        stream_verify=args.stream_verify,
        stream_verify_cap=args.stream_verify_cap,
        direct_probe=args.direct_probe,
    )

    t0 = time.time()
    try:
        if args.pivot:
            findings = run_with_pivot(base, wordlist, scan_kwargs,
                                       pivot_depth=args.pivot_depth,
                                       max_pivot_endpoints=args.pivot_max,
                                       printer=printer)
        else:
            scanner = Scanner(base_req=base, printer=printer, **scan_kwargs)
            findings = scanner.run(wordlist)
    except KeyboardInterrupt:
        log('\n[!] Interrupted'); findings = []
    finally:
        printer.finish()

    log(f'\n[+] Done in {time.time()-t0:.1f}s. Total: {len(findings)} param(s)')

    if not findings:
        print('  (no parameters detected)')

    if args.output:
        out = []
        for f in findings:
            ctxs_ser = []
            for cn, ctxs in f.contexts:
                for ctx_name, snippet, pos in ctxs:
                    info = CONTEXT_INFO.get(ctx_name, (0, 'unknown', ''))
                    ctxs_ser.append({'canary': cn, 'context': ctx_name,
                                     'vuln_class': info[1], 'snippet': snippet,
                                     'suggested_payload': info[2]})
            out.append({'name': f.name, 'confidence': f.score,
                        'reasons': f.reasons, 'endpoint': f.endpoint,
                        'contexts': ctxs_ser, 'pivot_urls': list(f.pivot_urls)})
        with open(args.output, 'w') as fh: json.dump(out, fh, indent=2)
        log(f'[+] Saved JSON to {args.output}')


# ============================================================================
#  SELFTEST (компактный)
# ============================================================================

def _silent_log(self, *args, **kwargs): pass


class _SBasic(BaseHTTPRequestHandler):
    log_message = _silent_log
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        body = '<html><body>Welcome'
        if 'debug' in params: body += '<pre>DEBUG: db=internal</pre>'
        if 'cache_refresh' in params: time.sleep(0.060)
        if 'lang' in params:
            l = re.sub(r'[<>"\']', '', params['lang'][0])[:20]
            body += f'<html lang="{l}">'
        if params.get('admin', [''])[0] == 'true':
            body += '<div>SECRET</div>'
        body += '</body></html>'
        b = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers(); self.wfile.write(b)


class _SPivot(BaseHTTPRequestHandler):
    """/ + ?next=X -> href со step2. /step2/ + ?secret=Y -> diff."""
    log_message = _silent_log
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path.startswith('/step2'):
            body = '<html><body><h1>Step 2</h1>'
            if 'secret' in params: body += '<p>SECRET FOUND</p>'
            body += '</body></html>'
        else:
            nxt = params.get('next', [''])[0][:30]
            nxt = re.sub(r'[<>"\']', '', nxt)
            body = f'<html><body><a href="/step2/?ref={nxt}">next</a></body></html>'
        b = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers(); self.wfile.write(b)


class _ReusableThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]; s.close(); return p


def run_selftest():
    print('=== paraminer v0.5 self-test ===\n')

    # Test 1: basic oracles
    print('--- Test 1: oracles (diff/time/reflection/cache) ---')
    port = _free_port()
    srv = _ReusableThreadingServer(('127.0.0.1', port), _SBasic)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)

    wordlist = ['id', 'user', 'name', 'token', 'page', 'limit', 'sort', 'q',
                'session', 'role', 'admin', 'debug', 'cache_refresh', 'lang',
                'view', 'theme', 'beta', 'preview', 'count']
    random.shuffle(wordlist)
    expected = {'debug', 'cache_refresh', 'lang', 'admin'}

    printer = StreamPrinter(quiet=False)
    scanner = Scanner(
        base_req={'method': 'GET', 'url': f'http://127.0.0.1:{port}/',
                  'headers': {}, 'body': None},
        mode='query', timeout=10, chunk_size=10, threads=2,
        calibration_n=10, confidence_threshold=0.5,
        time_threshold_mads=4.0, verify=True, quiet=False,
        p_value_threshold=0.01, printer=printer, rate_limit_adapt=False)
    t0 = time.time()
    f1 = scanner.run(wordlist)
    printer.finish()
    print(f'  Result: {sorted(f.name for f in f1)} | expected {sorted(expected)} | '
          f'{time.time()-t0:.1f}s')
    found = {f.name for f in f1}
    ok1 = expected.issubset(found) and not (found - expected)
    print(f'  {"[PASS]" if ok1 else "[FAIL]"}\n')
    srv.shutdown()

    # Test 2: pivot
    print('--- Test 2: pivot discovery ---')
    port2 = _free_port()
    srv2 = _ReusableThreadingServer(('127.0.0.1', port2), _SPivot)
    threading.Thread(target=srv2.serve_forever, daemon=True).start()
    time.sleep(0.2)

    wordlist2 = ['id', 'name', 'page', 'q', 'sort', 'next', 'view',
                 'secret', 'admin', 'debug']
    random.shuffle(wordlist2)

    printer2 = StreamPrinter(quiet=False)
    scan_kwargs = dict(
        mode='query', timeout=10, chunk_size=8, threads=2,
        calibration_n=10, confidence_threshold=0.5,
        time_threshold_mads=4.0, verify=True, quiet=False,
        p_value_threshold=0.01, rate_limit_adapt=False,
        max_chunk_hits=8, exclude_error_statuses=False,
        skip_error_oracle=False, use_cache_oracle=True, enable_pivot=True)

    base_req2 = {'method': 'GET', 'url': f'http://127.0.0.1:{port2}/',
                 'headers': {}, 'body': None}
    findings2 = run_with_pivot(base_req2, wordlist2, scan_kwargs,
                                pivot_depth=1, max_pivot_endpoints=3,
                                printer=printer2)
    printer2.finish()
    names = [(f.name, f.endpoint) for f in findings2]
    base_url = f'http://127.0.0.1:{port2}/'
    found_next_on_base = any(n == 'next' and base_url in (e or '')
                              for n, e in names)
    found_secret_on_step2 = any(n == 'secret' and '/step2/' in (e or '')
                                 for n, e in names)
    ok2 = found_next_on_base and found_secret_on_step2
    print(f'  Findings: {names}')
    print(f'  next on base: {found_next_on_base}, '
          f'secret on /step2/: {found_secret_on_step2}')
    print(f'  {"[PASS]" if ok2 else "[FAIL]"}\n')
    srv2.shutdown()

    passed = sum([ok1, ok2])
    print(f'=== {passed}/2 tests passed ===')
    return 0 if passed == 2 else 1


if __name__ == '__main__':
    main()
