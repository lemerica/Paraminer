# paraminer

<div align="center">

**Многооракульный инструмент обнаружения скрытых HTTP-параметров**

[![Python](https://img.shields.io/badge/python-3.7%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](https://python.org)
[![Playwright](https://img.shields.io/badge/DOM--oracle-playwright-orange?logo=playwright)](https://playwright.dev)

</div>

---

`paraminer` находит скрытые HTTP-параметры, которые backend обрабатывает, но которые не объявлены во frontend. Инструмент комбинирует **12 независимых оракулов обнаружения**, статистический тест Mann-Whitney U для отсева ложных срабатываний и опциональный DOM-diff через Playwright. Не требует внешних зависимостей для базового режима — только стандартная библиотека Python.

---

## Содержание

- [Возможности](#возможности)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Флаги CLI](#флаги-cli)
- [Оракулы](#оракулы)
- [Pre-flight check](#pre-flight-check)
- [Интерпретация результатов](#интерпретация-результатов)
- [Рецепты](#рецепты)
- [Рекомендуемые wordlists](#рекомендуемые-wordlists)

---

## Возможности

| Функция | Описание |
|---------|----------|
| **12 оракулов** | diff, timing, reflection, header-reflection, cache-key, server-timing, cookie, JS-state, semantic probe, boolean-pair, pollution, error |
| **DOM-oracle** | Headless Chromium через Playwright: сравнение DOM, XHR, localStorage, sessionStorage — ловит параметры, незаметные в HTTP |
| **Pre-flight check** | Авто-определение CDN (Cloudflare, Fastly, Akamai, CloudFront), WAF, OAuth-strict, реактивности таргета — до начала сканирования |
| **Rate-limit governor** | Авто-снижение concurrency на 429/WAF challenge, постепенное восстановление |
| **Pivot-scanning** | Рекурсивное сканирование URL, найденных в reflection'ах (href, src, og:url, location.href) |
| **Stream-verify** | Верификация кандидатов параллельно с discovery — первые результаты через минуты, а не в конце |
| **Direct-probe mode** | Для CDN-кешируемых таргетов, где chunk-based diff бесполезен: полный per-param oracle stack |
| **Context classifier** | Определяет контекст reflection (html_text, js_string, href_attr, meta_url и др.) и предлагает payload |
| **JSON-вывод** | Экспорт с confidence, reasons, контекстом и pivot URL |

---

## Установка

```bash
git clone https://github.com/your-repository/paraminer.git
cd paraminer
```

Внешних зависимостей нет — запускается напрямую.

**Опционально — DOM-oracle** (требует ~300 MB для Chromium):

```bash
pip install playwright
playwright install chromium
```

---

## Быстрый старт

```bash
# Сканирование query-параметров (GET)
python paraminer.py -u https://example.com/api/users -w wordlist.txt

# POST JSON API
python paraminer.py -u https://example.com/api -w params.txt --json

# Из Burp-запроса
python paraminer.py -r request.txt -w params.txt

# Встроенные тесты (не требует сети)
python paraminer.py --selftest
```

---

## Флаги CLI

### Цель и запрос

| Флаг | Описание |
|------|----------|
| `-u, --url URL` | Целевой URL |
| `-r, --request FILE` | Raw HTTP-запрос в Burp-формате (альтернатива `-u`) |
| `-X, --method METHOD` | HTTP-метод (по умолчанию: `GET`) |
| `-H, --header "Name: val"` | Дополнительный заголовок (флаг повторяется) |
| `-d, --data STRING` | Тело запроса |
| `-b, --cookie STRING` | Значение Cookie |

### Режим инъекции

| Флаг | Описание |
|------|----------|
| `--mode {query,form,json,headers}` | Явно задать режим |
| `--json` | Сокращение для `--mode json` |
| `--form` | Сокращение для `--mode form` |
| `--headers` | Сокращение для `--mode headers` (fuzzing HTTP-заголовков) |

> Если режим не указан — выбирается автоматически: POST/PUT/PATCH + `Content-Type: application/json` → `json`, POST без JSON → `form`, GET → `query`.

### Производительность

| Флаг | По умолч. | Описание |
|------|-----------|----------|
| `-c, --threads N` | `4` | Число потоков |
| `-m, --chunk-size N` | `25` | Параметров в одном запросе |
| `-n, --calibration N` | `10` | Baseline-запросов до сканирования |
| `-t, --timeout SEC` | `15` | Timeout одного запроса (сек) |
| `--max-rps FLOAT` | `5.0` | Глобальный лимит req/s по всем потокам (`0` = без ограничений) |

### Тюнинг и фильтры

| Флаг | По умолч. | Описание |
|------|-----------|----------|
| `--confidence FLOAT` | `0.5` | Минимальный confidence для репорта (0–1) |
| `--p-value FLOAT` | `0.001` | p-value для time-oracle |
| `--max-chunk-hits N` | `8` | Макс. кандидатов из одного чанка (защита от шумных таргетов) |
| `--exclude-error-statuses` | — | Не репортить параметры, дающие только 4xx/5xx |
| `--skip-error-oracle` | — | Пропустить error-oracle (ускоряет verify в ~6×) |
| `--no-cache-oracle` | — | Отключить cache-key oracle |
| `--no-verify` | — | Только stage 1 без верификации (быстро, много FP) |

### Специальные режимы

| Флаг | Описание |
|------|----------|
| `--stream-verify` | Верифицировать кандидатов параллельно с discovery |
| `--stream-verify-cap N` | Макс. кандидатов в очереди stream-verify (по умолч. `500`) |
| `--direct-probe` | Per-param режим для CDN-кешируемых таргетов (~13–18 req/param) |
| `--pivot` | Авто-pivot по URL, найденным в reflection'ах |
| `--pivot-depth N` | Глубина рекурсии pivot (по умолч. `1`) |
| `--pivot-max N` | Макс. pivot-endpoints (по умолч. `10`) |

### DOM-oracle

| Флаг | Описание |
|------|----------|
| `--dom-oracle` | Включить DOM-diff oracle (требует Playwright + Chromium) |
| `--dom-timeout SEC` | Timeout для одного DOM-snapshot (по умолч. `20`) |

> DOM-oracle работает **только с** `--mode query`. Verify становится однопоточным (Playwright sync API thread-affinity). На 50 кандидатах добавляет ~1–2 мин.

### Прочее

| Флаг | Описание |
|------|----------|
| `--proxy URL` | HTTP-прокси (например, `http://127.0.0.1:8080` для Burp) |
| `-o, --output FILE` | Сохранить findings в JSON |
| `--no-color` | Отключить ANSI-цвета (авто при pipe/non-TTY) |
| `--no-preflight` | Пропустить pre-flight check |
| `--force-scan` | Игнорировать вердикт pre-flight и сканировать в любом случае |
| `--no-rate-limit-adapt` | Отключить авто-адаптацию на rate-limit (по умолч. включена) |
| `--selftest` | Встроенные тесты (поднимает локальные серверы, не требует сети) |

---

## Оракулы

| # | Оракул | Триггер |
|---|--------|---------|
| 1 | **diff** | Изменение статуса, длины тела или уникальных строк относительно baseline |
| 2 | **time** | Статистически значимая задержка по Mann-Whitney U (p < 0.001 по умолч.) |
| 3 | **reflection** | Canary-строка в теле ответа с классификацией контекста |
| 4 | **header_reflection** | Canary в response-заголовках (Location, Set-Cookie, Link и др.) |
| 5 | **cache_key** | Изменение CDN cache-статуса (cf-cache-status, x-cache, age) |
| 6 | **server_timing** | Аномалия метрик в заголовке `Server-Timing` (> 3 MAD) |
| 7 | **cookie** | Появление новых нетривиальных `Set-Cookie` |
| 8 | **js_state** | Изменение inline JS-состояния (`__NEXT_DATA__`, `__INITIAL_STATE__`, Apollo, Nuxt и др.) |
| 9 | **semantic_probe** | ≥ 4 distinct response signatures при разных типах значений (int, bool, null, array…) |
| 10 | **boolean_pair** | Стабильно разные ответы на противоположные значения (`1`/`0`, `true`/`false`) |
| 11 | **pollution** | Изменение ответа при дублировании ключа (HPP) |
| 12 | **error** | Различные error-состояния на edge-значения (очень длинная строка, пустое, шаблонный синтаксис) |
| ✦ | **DOM-diff** | Изменение DOM/XHR/localStorage/sessionStorage/cookies после выполнения JS (Playwright) |

Итоговый confidence рассчитывается через байесовское перемножение оракулов: `1 - ∏(1 - score_i)`. Параметр выводится только если хотя бы один оракул дал `score ≥ 0.55`.

---

## Pre-flight check

Перед сканированием paraminer автоматически делает 6–12 диагностических запросов:

- Определяет **CDN/кеш** (Cloudflare, Fastly, Akamai, CloudFront, Varnish, Azure Front Door)
- Определяет **WAF** (Cloudflare challenge, AWS WAF, Akamai, Imperva)
- Проверяет **OAuth strict-validation** (redirect при неизвестных параметрах)
- Тестирует **реактивность** таргета на известные параметры

Если таргет признан **non-reactive** — сканирование останавливается с пояснением и рекомендациями. Флаги для управления: `--force-scan`, `--direct-probe`, `--no-preflight`.

---

## Интерпретация результатов

```
[0.96] secret_key  @ https://example.com/api/v1
   |- canary 'cn4f7a3b1c' reflected -> context='js_string_double'
   |- context=js_string_double -> XSS via JS string break (")
      payload: ";alert(1);//

[0.78] debug  @ https://example.com/api/v1
   |- status=200 (baseline: [404])
   |- line-diff: '<pre>DEBUG: db=internal host=...</pre>'
```

| Score | Значение |
|-------|----------|
| `0.95–1.00` | Высокая уверенность: изменение статуса или сильный content diff |
| `0.85–0.94` | Несколько оракулов сошлись — скорее всего реальный параметр |
| `0.60–0.84` | Один сильный сигнал — стоит проверить вручную |
| `0.50–0.59` | Слабые сигналы — возможны FP, но иногда rate-limited param |

### Контексты reflection и соответствующие уязвимости

| Контекст | Класс уязвимости | Пример payload |
|----------|-----------------|----------------|
| `html_text` | Reflected XSS | `<svg/onload=alert(1)>` |
| `js_string_double` | XSS через разрыв JS-строки | `";alert(1);//` |
| `js_string_single` | XSS через разрыв JS-строки | `';alert(1);//` |
| `js_template` | XSS через template literal | `${alert(1)}` |
| `script_block` | Прямое исполнение JS | `;alert(1)//` |
| `href_attr` | Open Redirect / XSS | `javascript:alert(1)` |
| `src_attr` | XSS через src= | `data:text/html,<script>alert(1)</script>` |
| `url_path` / `url_host` | Open Redirect / SSRF | `//evil.com` |
| `meta_url_canonical` | Canonical poisoning / SEO | `//evil/` |
| `header_value` | CRLF / Cache poisoning | `\r\nSet-Cookie:x=y` |

---

## Рецепты

```bash
# Агрессивный таргет (Cloudflare, WAF, rate-limit)
python paraminer.py -u https://target.com/api -w params.txt \
  -c 2 -m 10 --max-chunk-hits 3 \
  --exclude-error-statuses --skip-error-oracle

# JSON API, быстрый прогон
python paraminer.py -u https://target.com/api -w params.txt \
  --json -c 4 -m 15 --confidence 0.45 --skip-error-oracle

# Большой wordlist (50k+): результаты по мере нахождения
python paraminer.py -u https://target.com/ -w big.txt \
  -c 6 -m 25 --stream-verify -o results.json

# SPA на React/Vue/Angular (DOM-oracle)
python paraminer.py -u https://target.com/ -w params.txt \
  --dom-oracle --confidence 0.5 -c 2

# CDN-кешируемый таргет (обычный diff бесполезен)
python paraminer.py -u https://target.com/ -w params.txt \
  --direct-probe -c 4

# Через Burp с прокси
python paraminer.py -r request.txt -w params.txt \
  --proxy http://127.0.0.1:8080

# Ночной прогон с pivot
python paraminer.py -u https://target.com/ -w params.txt \
  -c 6 -m 25 --pivot --pivot-depth 2 -o results.json

# Termux / слабая машина
python paraminer.py -u https://target.com/ -w params.txt \
  -c 2 -m 20 --no-color --skip-error-oracle
```

---

## Рекомендуемые wordlists

| Размер | Ссылка | Когда использовать |
|--------|--------|--------------------|
| 1–5k | [Arjun params.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/params.txt) | Быстрый прогон, слабая машина |
| 50k+ | [PortSwigger param-miner](https://github.com/PortSwigger/param-miner) | Полное покрытие |

> Tech-specific wordlists работают лучше generic. WordPress — добавь `preview`, `p`, `cat`, `rest_route`. Laravel/Symfony — `_token`, `_method`.

---

## Требования

- **Python 3.7+**
- Стандартная библиотека Python (без `pip` для базового режима)
- **Playwright** (опционально, только для `--dom-oracle`):
  ```bash
  pip install playwright && playwright install chromium
  ```
