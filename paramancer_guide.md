# Paraminer — полное руководство по использованию

`paraminer.py` — мульти-оракульный сканер скрытых HTTP-параметров. Ищет параметры
(query / body / json / headers), которые обрабатывает бэкенд, но которых нет
во фронтенде. Single-file, только стандартная библиотека Python (DOM-oracle —
опционально через Playwright). Работает на Linux / macOS / Termux.

---

## Оглавление

1. [Как это работает (модель)](#1-как-это-работает-модель)
2. [Установка и запуск](#2-установка-и-запуск)
3. [Два способа задать цель: -u и -r](#3-два-способа-задать-цель)
4. [Режимы инъекции (mode)](#4-режимы-инъекции)
5. [Оракулы — что и как детектит](#5-оракулы)
6. [Три режима сканирования](#6-три-режима-сканирования)
7. [Pre-flight check](#7-pre-flight-check)
8. [Rate limiting и WAF](#8-rate-limiting-и-waf)
9. [DOM-oracle (SPA)](#9-dom-oracle)
10. [Pivot (рекурсивный скан)](#10-pivot)
11. [Полный справочник флагов](#11-полный-справочник-флагов)
12. [Готовые рецепты под тип цели](#12-готовые-рецепты)
13. [Как читать вывод](#13-как-читать-вывод)
14. [Wordlists](#14-wordlists)
15. [Что делать ПОСЛЕ находки](#15-что-делать-после-находки)
16. [Troubleshooting](#16-troubleshooting)
17. [Чеклист багбаунт прогона](#17-чеклист)

---

## 1. Как это работает (модель)

Идея: послать запрос с параметром, которого фронтенд не использует, и понять по
ответу, заметил ли его бэкенд. Сам по себе один запрос ничего не скажет —
ответы шумят (таймстампы, CSRF, сетевой джиттер). Поэтому Paramancer:

1. Калибруется — делает N запросов без параметров и запоминает «нормальный»
   диапазон (статусы, длины, тайминги TTFB, стабильные строки тела,
   Server-Timing, cookies, inline-state).
2. Ищет кандидатов (discovery) — быстро прогоняет словарь.
3. Верифицирует каждого кандидата множеством независимых оракулов и
   агрегирует их в итоговый confidence.

Ключевой принцип последней версии: находка засчитывается, только если есть
хотя бы один самостоятельно убедительный сигнал (score ≥ 0.55). Несколько
слабых/шумовых сигналов больше не «складываются» в ложную находку.

---

## 2. Установка и запуск

```bash
# Базово — ничего ставить не надо, только Python 3.7+
python3 paraminer.py --help
python3 paraminer.py --help-ru      # подробная встроенная справка на русском
python3 paraminer.py --selftest     # самотест (поднимает локальные серверы)

# Опционально — DOM-oracle для SPA:
pip install playwright
playwright install chromium      # ~300 МБ
```

Termux (Android): работает из коробки, добавляй `--no-color` и
`--skip-error-oracle` для экономии.

---

## 3. Два способа задать цель

### `-u/--url` — простой
```bash
python3 paraminer.py -u "https://target/api/users" -w params.txt
```
Доп. опции к нему: `-X POST`, `-H "Authorization: Bearer ..."`,
`-d 'body'`, `-b 'session=...'` (cookie).

### `-r/--request` — raw HTTP request (как из Burp)
Сохрани запрос из бурпа/каидо в файл `req.txt`:
```
GET /api/v1/users HTTP/1.1
Host: target.com
Authorization: Bearer eyJ...
Cookie: session=abc123
User-Agent: Mozilla/5.0
```
```bash
python3 paraminer.py -r req.txt -w params.txt
```
Это предпочтительный способ для аутентифицированного скана — сохраняет все
заголовки и сессию. Большинство интересных параметров живут за авторизацией.

---

## 4. Режимы инъекции

Куда подставлять параметры. Выбирается автоматически по методу/Content-Type,
но можно задать явно:

| Флаг | Mode | Куда вставляет | Когда |
|------|------|----------------|-------|
| (авто, GET) | `query` | `?param=val` | GET-эндпоинты, поиск, фильтры |
| `--form` | `form` | тело `application/x-www-form-urlencoded` | классические POST-формы |
| `--json` | `json` | ключи в JSON-тело | REST/API |
| `--headers` | `headers` | как HTTP-заголовки | фаззинг заголовков (X-Forwarded-*, и т.п.) |
| `--mode X` | явно | — | переопределить авто |

Авто-логика: `POST/PUT/PATCH` + `Content-Type: json` → `json`, иначе `form`;
всё прочее → `query`.

---

## 5. Оракулы

Оракул — независимый детектор «бэкенд среагировал». Каждый даёт score 0..1.
Итог агрегируется, плюс действует gate ≥0.55.

| Оракул | Что ловит | Сильный сигнал |
|--------|-----------|----------------|
| diff | изменение статуса / длины / строк тела относительно baseline | смена статус-кода |
| time (Mann-Whitney U) | стабильное замедление по TTFB (доп. обработка на бэке) | низкий p-value на стабильной цели |
| reflection | канарейка отражена в теле + классификация контекста (XSS/redirect/...) | канарейка в HTML/JS |
| header-reflection ★ | канарейка в Location/Set-Cookie/Content-Disposition/Link | отражение в Location |
| pollution / HPP ★ | дубль ключа `p=a&p=b` меняет ответ → бэкенд разбирает ключ | разная сигнатура одиночного и дубля |
| boolean-pair ★ | пара противоположных значений даёт стабильно разный ответ | 2+ стабильных расхождения |
| semantic-probe | разные типы значений (int/null/array/...) → разные сигнатуры | 4+ distinct сигнатур |
| cache-key | смена cf-cache-status / x-cache / age | MISS/BYPASS на фоне baseline-HIT |
| server-timing | аномалия в Server-Timing метриках сквозь CDN-кэш | >3 MAD отклонение |
| cookie | новый осмысленный Set-Cookie (не session/csrf) | новый именованный cookie |
| error | разные значения → разные error-состояния | 3+ distinct состояния |
| js-state | изменение inline-state SPA (__NEXT_DATA__, __NUXT__, Apollo, Vuex...) | diff состояния >5 байт |
| DOM-diff | сравнение страницы после исполнения JS (XHR/storage/console) | канарейка в XHR-URL |

★ — техники, добавленные в этой версии. Особенно ценны на CDN-кэшированных и
non-reactive целях, где обычный diff слеп. `boolean-pair` — главный антишумовой
детектор: случайный джиттер не даёт стабильного расхождения.

Какие оракулы когда работают:
- discovery-стадия (chunk-based): только diff + reflection (быстро).
- verify-стадия: весь стек.
- direct-probe: сразу весь стек по каждому параметру (discovery пропускается).

---

## 6. Три режима сканирования

### A. Batched (по умолчанию)
Сначала весь discovery по чанкам (склеивает несколько параметров в один запрос
+ bisection), потом верификация уникальных кандидатов.

```bash
python3 paraminer.py -u URL -w params.txt
```
- Быстрый на больших словарях.
- Подходит для реактивных целей (отвечают на параметры заметно для diff).
- Лимит: верифицируется максимум 200 топ-кандидатов по confidence.

### B. Stream-verify (`--stream-verify`)
Discovery и verify работают параллельно через очередь: реальные находки
всплывают в первые минуты, а не в конце.

```bash
python3 paraminer.py -u URL -w big_50k.txt --stream-verify
```
- Для очень больших словарей (50k+), когда discovery идёт часами.
- `--stream-verify-cap N` — защита от echo-целей (макс. кандидатов в очереди).

### C. Direct-probe (`--direct-probe`) — для CDN / non-reactive
Полностью обходит chunk-discovery. Гоняет полный verify (включая
принудительные boolean-pair / pollution / semantic-probe) по каждому
параметру отдельно.

```bash
python3 paraminer.py -r req.txt -w focused.txt --direct-probe
```
- Когда pre-flight говорит «NON-REACTIVE» (кэш / SSO-редирект / WAF глотает
  query) — это единственный рабочий путь.
- Diff против uncached-baseline там бесполезен; помогают сигнатурные оракулы.
- Дорого: ~13–18 запросов на параметр. На 99k словаре это сотни тысяч
  запросов — тебя забанят. Используй сокращённый/таргетированный словарь
  (сотни–тысячи имён, например выжимку из JS-рекона).
---

## 7. Pre-flight check

Перед сканом (если не отключён `--no-preflight`) делается быстрая диагностика
(6–12 запросов): CDN/кэш, WAF, OAuth-редирект, реагирует ли цель на параметры
вообще.

- Если цель NON-REACTIVE — скан останавливается с объяснением.
- Переопределить: `--direct-probe` (правильный путь для CDN) или
  `--force-scan` (сканить как есть).

```bash
# pre-flight сказал non-reactive → используем правильный режим:
python3 paraminer.py -r req.txt -w focused.txt --direct-probe --force-scan
```

---

## 8. Rate limiting и WAF

### Глобальный лимит запросов — `--max-rps` (ДЕФОЛТ 5.0)
Ограничивает суммарную частоту по всем потокам.
```bash
--max-rps 4        # с запасом под лимит 5/сек
--max-rps 0        # без ограничения (ТОЛЬКО свой стенд!)
```

### Авто-адаптация под 429/WAF (вкл. по умолчанию)
Governor сам замедляется на 429/Cloudflare/AWS WAF тремя уровнями (SOFT/HARD/
CRITICAL) и не разгоняется обратно. Отключить: `--no-rate-limit-adapt`.

### `-c/--threads` — потоки
Не больше 2–4 на серьёзную цель. С `--max-rps` потоки всё равно упрутся в общий
лимит, так что много потоков = просто ожидание токенов.

---

## 9. DOM-oracle

Для SPA (React/Vue/Angular), где параметр меняет только client-side рендер и
невидим для HTTP-diff. Запускает headless Chromium, сравнивает страницу после
исполнения JS: DOM, XHR-запросы, localStorage, console, cookies.

```bash
python3 paraminer.py -u URL -w focused.txt --dom-oracle --dom-timeout 20
```
- Только `mode=query`.
- Требует `playwright` + `chromium`.
- Медленно: verify становится однопоточным (Playwright thread-affinity),
  1–3 сек на снимок. Используй на маленьких словарях (50–200) или поверх
  кандидатов.
- Если не установлен/упал baseline — тихо отключается, остальной скан идёт.
- В этой версии не считает за сигнал канарейку, осевшую в адресной строке после
  редиректа (типовой ложный сигнал на /login).

---

## 10. Pivot

Когда канарейка попадает в URL внутри ответа (href, src, og:url,
location.href), Paramancer добавляет этот URL в очередь и сканирует тем же
словарём. Same-origin only.

```bash
python3 paraminer.py -u https://target/ -w params.txt --pivot --pivot-depth 1 --pivot-max 10
```

---

## 11. Полный справочник флагов

### Цель и запрос
| Флаг | Дефолт | Описание |
|------|--------|----------|
| `-u, --url URL` | — | целевой URL |
| `-r, --request FILE` | — | raw HTTP request (Burp-style) |
| `-w, --wordlist FILE` | — | словарь параметров (`-` = stdin) |
| `-X, --method` | GET | HTTP-метод |
| `-H, --header "K: V"` | — | доп. заголовок (повторяется) |
| `-d, --data STR` | — | тело запроса |
| `-b, --cookie STR` | — | Cookie header |

### Режим инъекции
| Флаг | Описание |
|------|----------|
| `--mode {query,form,json,headers}` | явный режим |
| `--json` / `--form` / `--headers` | шорткаты |

### Производительность
| Флаг | Дефолт | Описание |
|------|--------|----------|
| `-c, --threads N` | 4 | потоки (2–4 на боевую цель) |
| `-m, --chunk-size N` | 25 | параметров в одном запросе (discovery) |
| `-n, --calibration N` | 10 | baseline-запросов |
| `-t, --timeout SEC` | 15 | таймаут запроса |
| `--max-rps F` | 5.0 | глоб. лимит запросов/сек (0 = выкл) |

### Тюнинг оракулов
| Флаг | Дефолт | Описание |
|------|--------|----------|
| `--confidence F` | 0.5 | мин. итоговый confidence |
| `--p-value F` | 0.001 | порог для time-oracle |
| `--time-threshold F` | 4.0 | MAD-порог (легаси) |
| `--max-chunk-hits N` | 8 | макс. кандидатов из чанка (обрезает, не выбрасывает) |
| `--exclude-error-statuses` | — | не репортить 4xx/5xx-only (WP/Drupal) |
| `--skip-error-oracle` | — | пропустить error/semantic-пробы (быстрее в ~6×) |
| `--no-cache-oracle` | — | отключить cache-key oracle |

### Режимы скана
| Флаг | Описание |
|------|----------|
| `--no-verify` | только discovery (быстро, шумно) |
| `--stream-verify` | discovery+verify параллельно |
| `--stream-verify-cap N` | макс. очередь (дефолт 500) |
| `--direct-probe` | по-параметрный полный verify (CDN/non-reactive) |

### DOM-oracle
| Флаг | Дефолт | Описание |
|------|--------|----------|
| `--dom-oracle` | — | включить (нужен playwright+chromium) |
| `--dom-timeout SEC` | 20 | таймаут снимка |

### Pivot
| Флаг | Дефолт | Описание |
|------|--------|----------|
| `--pivot` | — | вкл. авто-pivot |
| `--pivot-depth N` | 1 | глубина |
| `--pivot-max N` | 10 | макс. эндпоинтов |

### Pre-flight / WAF
| Флаг | Описание |
|------|----------|
| `--no-preflight` | пропустить диагностику |
| `--force-scan` | игнорировать вердикт non-reactive |
| `--no-rate-limit-adapt` | отключить авто-замедление на 429/WAF |
| `--no-stream-candidates` | не показывать неподтверждённых кандидатов |

### Вывод / прочее
| Флаг | Описание |
|------|----------|
| `--proxy URL` | HTTP-прокси (например Burp `http://127.0.0.1:8080`) |
| `-o, --output FILE` | сохранить findings в JSON |
| `--no-color` | без ANSI |
| `--selftest` | самотест |
| `--help-ru` / `-hr` | подробная справка |

---

## 12. Готовые рецепты

Аутентифицированный API (REST/JSON):
```bash
python3 paraminer.py -r req.txt -w api_params.txt --json \
  -c 2 --max-rps 4 --skip-error-oracle --confidence 0.45
```

CDN-кэшированная / non-reactive цель (твой hrlink-кейс):
```bash
python3 paraminer.py -r req.txt -w focused.txt \
  --direct-probe --force-scan -c 2 --max-rps 4
```

SPA (React/Vue) на маленьком словаре:
```bash
python3 paraminer.py -u https://app/page -w small_200.txt \
  --dom-oracle -c 2 --max-rps 4 --confidence 0.5
```

Большой словарь, хочу находки пораньше:
```bash
python3 paraminer.py -r req.txt -w big_50k.txt \
  --stream-verify --max-rps 4 --skip-error-oracle
```

Агрессивный WAF (Cloudflare/AWS):
```bash
python3 paraminer.py -r req.txt -w focused.txt \
  -c 2 -m 10 --max-chunk-hits 3 --max-rps 3 \
  --exclude-error-statuses --skip-error-oracle
```

Через Burp (для ручного просмотра трафика):
```bash
python3 paraminer.py -r req.txt -w params.txt --proxy http://127.0.0.1:8080 --max-rps 4
```

Фаззинг заголовков:
```bash
python3 paraminer.py -u https://target/ -w header_names.txt --headers --max-rps 4
```

Сохранить результат для отчёта:
```bash
python3 paraminer.py -r req.txt -w params.txt --direct-probe -o findings.json --max-rps 4
```

---

## 13. Как читать вывод

```
[0.85] redirect_uri  @ https://target/
   |- canary reflected in response header 'location'
```
- `[0.85]` — итоговый confidence.
- `redirect_uri` — имя параметра, `@` — эндпоинт.
- `|-` — какой оракул и почему сработал.

Шкала:
| Score | Трактовка | Действие |
|-------|-----------|----------|
| 1.00 | сменился статус-код (404/302/500) | часто роутер/WAF — проверь руками |
| 0.95 | канарейка в теле / сильный diff | почти точно реальный |
| 0.85–0.94 | несколько оракулов сошлись | реальный, в работу |
| 0.60–0.84 | один сильный сигнал | проверь руками |
| 0.50–0.59 | слабый | часто FP (в этой версии их сильно меньше) |

Маркер `?` (`[0.65]?`) = неподтверждённый кандидат discovery-стадии, ждёт verify.

Context-классификатор подсказывает класс уязвимости для отражённых параметров:
`html_text` → XSS, `href_attr`/`url_path` → open-redirect, `js_string_*` → XSS
в JS, `meta_url_canonical` → canonical poisoning. Это гипотезы, не находки.

---

## 14. Wordlists

- Маленький (1–5k) — быстрые прогоны, Termux, direct-probe:
  Arjun `params.txt`.
- Большой (50k+) — зрелые программы: PortSwigger `param-miner` wordlist.
- Tech-specific работают лучше generic: WordPress (`preview`, `p`, `cat`,
  `rest_route`), Laravel (`_token`, `_method`), и т.п.
- JS-рекон — лучший источник: имена параметров, выдранные из JS самого
  приложения. Объедини с generic, дедуплицируй:
  ```bash
  cat jsrecon_params.txt arjun_params.txt | sort -u > focused.txt
  ```

Для direct-probe используй именно focused-словарь (сотни–тысячи), не 99k.

---

## 15. Что делать ПОСЛЕ находки

Параметр — это вход, а не уязвимость. Дальше вручную:

1. Подтверди в Burp/браузере, что параметр реально влияет на ответ.
2. Прозондируй значениями: пусто, длинное, отрицательное, чужой ID, JSON,
   спец-символы, path-traversal.
3. Сопоставь с классом уязвимости под программу:
   - `id`/`*Id`/`employeeId`/`legalEntityId` → IDOR (подставь чужой объект).
   - `url`/`redirect`/`next`/`callback`/`*_uri` → open-redirect / SSRF.
   - `file`/`path`/`template`/`include` → LFI/RFI / SSTI.
   - отражение в теле → XSS (если влияет на чужие/чувствительные данные).
   - `role`/`admin`/`debug`/`is_*` → обход авторизации / privilege escalation.
4. Собери PoC строго в рамках testing policy программы (для RCE/SQLi/LFR —
   только разрешённые действия!).
5. Репорти одну уязвимость = один отчёт, с шагами и доказательством.

> Raw-вывод сканера в отчёт не вставляй — его не примут. Нужна
> подтверждённая уязвимость с воспроизведением.

---

## 16. Troubleshooting

«Из словаря находит 0–1 параметр»
На большом словаре в batched-режиме сигнал одного параметра тонет в чанке.
Решение: `-m 5` (меньше чанк), `--confidence 0.35`, `--stream-verify`. На
CDN-цели — `--direct-probe`.

«Все находки с одинаковым score (напр. 0.78)»
Это были шумовые FP (timing-джиттер + redirect-echo). В текущей версии
устранены: gate ≥0.55 + фильтр канарейки в final_url + ужесточённый timing.
Если всё ещё видишь — подними `--confidence 0.6`.

«Pre-flight: NON-REACTIVE, скан остановился»
Цель за кэшем/SSO. Используй `--direct-probe --force-scan`. Если и так пусто —
landing честно не принимает параметры; ищи реальные API-эндпоинты за авторизацией.

«Очень медленно»
Это `--max-rps 5` (специально, под правила). На своём стенде — `--max-rps 0`.
Плюс `--skip-error-oracle` ускоряет verify в ~6 раз.

«Rate-limit / 429 / WAF challenge»
Снизь `--max-rps 2-3`, `-c 2`, добавь `--max-chunk-hits 3`. Авто-адаптация уже
включена.

«DOM-oracle не работает»
`pip install playwright && playwright install chromium`. Только `mode=query`.
На больших словарях не используй — однопоточный и медленный.

«Нужна сессия / куки»
Используй `-r req.txt` с полным запросом из Burp (сохранит Cookie/Authorization).

---

## 17. Чеклист багбаунт прогона

- [ ] Цель в scope активной программы / это мой стенд.
- [ ] Прочитал testing policy (что можно при RCE/SQLi/LFR/этцетра).
- [ ] `--max-rps` ≤ лимита программы (дефолт 5, ставлю 4 для запаса).
- [ ] Запрос с сессией сохранён в `req.txt` (`-r`).
- [ ] Выбран правильный режим: реактивная -> batched/stream; CDN -> direct-probe.
- [ ] Словарь подходящий: focused для direct-probe, большой для stream.
- [ ] Результаты в `-o findings.json`.
- [ ] Каждую находку проверил вручную перед выводами.
- [ ] В отчёт идёт подтверждённая уязвимость + PoC, НЕ вывод сканера.
- [ ] Конфиденциальность: не публикую найденное без разрешения программы.

---
