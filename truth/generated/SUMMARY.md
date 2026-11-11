# Ground truth summary

Total cases: 175

## kind

| Value | Count |
|---|---:|
| trap | 75 |
| vuln | 100 |

## owasp_2021

| Value | Count |
|---|---:|
| A01:2021 | 45 |
| A02:2021 | 11 |
| A03:2021 | 32 |
| A04:2021 | 17 |
| A05:2021 | 21 |
| A06:2021 | 5 |
| A07:2021 | 12 |
| A08:2021 | 13 |
| A09:2021 | 9 |
| A10:2021 | 10 |

## owasp_2025

| Value | Count |
|---|---:|
| A01:2025 | 45 |
| A02:2025 | 21 |
| A03:2025 | 5 |
| A04:2025 | 11 |
| A05:2025 | 32 |
| A06:2025 | 17 |
| A07:2025 | 12 |
| A08:2025 | 13 |
| A09:2025 | 9 |
| A10:2025 | 10 |

## cwe

| Value | Count |
|---|---:|
| CWE-1104 | 4 |
| CWE-113 | 2 |
| CWE-117 | 2 |
| CWE-1284 | 2 |
| CWE-1321 | 3 |
| CWE-1333 | 2 |
| CWE-1336 | 4 |
| CWE-1395 | 1 |
| CWE-20 | 16 |
| CWE-200 | 4 |
| CWE-204 | 2 |
| CWE-209 | 2 |
| CWE-22 | 8 |
| CWE-250 | 2 |
| CWE-269 | 1 |
| CWE-287 | 2 |
| CWE-294 | 1 |
| CWE-321 | 1 |
| CWE-327 | 3 |
| CWE-328 | 3 |
| CWE-330 | 2 |
| CWE-338 | 2 |
| CWE-345 | 4 |
| CWE-347 | 3 |
| CWE-359 | 2 |
| CWE-362 | 6 |
| CWE-367 | 2 |
| CWE-377 | 2 |
| CWE-384 | 2 |
| CWE-434 | 1 |
| CWE-502 | 5 |
| CWE-532 | 2 |
| CWE-552 | 2 |
| CWE-601 | 3 |
| CWE-611 | 2 |
| CWE-639 | 8 |
| CWE-682 | 2 |
| CWE-732 | 2 |
| CWE-78 | 7 |
| CWE-79 | 5 |
| CWE-798 | 2 |
| CWE-840 | 5 |
| CWE-862 | 4 |
| CWE-89 | 12 |
| CWE-915 | 5 |
| CWE-918 | 11 |
| CWE-942 | 5 |
| CWE-943 | 2 |

## severity

| Value | Count |
|---|---:|
| critical | 10 |
| high | 90 |
| info | 75 |

## difficulty

| Value | Count |
|---|---:|
| 1 | 47 |
| 2 | 47 |
| 3 | 41 |
| 4 | 40 |

## language

| Value | Count |
|---|---:|
| archive | 1 |
| backup | 1 |
| example | 1 |
| hardened | 1 |
| js | 107 |
| json | 2 |
| py | 58 |
| txt | 2 |
| yml | 2 |

## service

| Value | Count |
|---|---:|
| app_node | 107 |
| app_python | 55 |
| none | 13 |

## split

| Value | Count |
|---|---:|
| dev | 123 |
| test | 52 |

## Cases

| ID | Kind | OWASP 2021 | OWASP 2025 | Severity | Difficulty | Locations |
|---|---|---|---|---|---:|---|
| PV-0001 | vuln | A03:2021 | A05:2025 | high | 1 | app_node/controllers/userController.js:9-9 |
| PV-0002 | vuln | A03:2021 | A05:2025 | high | 1 | app_node/controllers/userController.js:19-19 |
| PV-0003 | vuln | A03:2021 | A05:2025 | high | 2 | app_node/controllers/searchController.js:8-8 |
| PV-0004 | vuln | A03:2021 | A05:2025 | high | 1 | app_python/app.py:555-555 |
| PV-0005 | vuln | A03:2021 | A05:2025 | high | 2 | app_node/controllers/feedbackController.js:21-21 |
| PV-0006 | vuln | A05:2021 | A02:2025 | high | 2 | app_python/xml_parser.py:19-19 |
| PV-0007 | vuln | A05:2021 | A02:2025 | high | 1 | app_node/controllers/searchController.js:90-90 |
| PV-0008 | vuln | A03:2021 | A05:2025 | high | 1 | app_node/controllers/searchController.js:110-110 |
| PV-0009 | vuln | A03:2021 | A05:2025 | high | 2 | app_node/services/mergeUtil.js:7-7 |
| PV-0010 | vuln | A03:2021 | A05:2025 | high | 2 | app_node/controllers/catalogController.js:21-21 |
| PV-0011 | vuln | A03:2021 | A05:2025 | high | 2 | app_python/diagnostic_service.py:19-19 |
| PV-0012 | vuln | A03:2021 | A05:2025 | high | 4 | app_node/models/dbClient.js:32-32 |
| PV-0013 | vuln | A03:2021 | A05:2025 | high | 3 | app_node/controllers/templateController.js:15-15 |
| PV-0014 | vuln | A03:2021 | A05:2025 | high | 3 | app_node/controllers/reportController.js:16-16 |
| PV-0015 | vuln | A03:2021 | A05:2025 | high | 4 | app_python/app.py:919-919 |
| PV-0016 | vuln | A03:2021 | A05:2025 | high | 4 | app_python/app.py:933-933 |
| PV-0017 | vuln | A03:2021 | A05:2025 | high | 4 | app_node/services/billingService.js:33-33 |
| PV-0018 | vuln | A01:2021 | A01:2025 | high | 1 | app_node/controllers/searchController.js:66-66 |
| PV-0019 | vuln | A01:2021 | A01:2025 | high | 1 | app_node/controllers/searchController.js:26-26 |
| PV-0020 | vuln | A01:2021 | A01:2025 | high | 2 | app_python/archive_extractor.py:22-22 |
| PV-0021 | vuln | A01:2021 | A01:2025 | high | 2 | app_node/controllers/uploadController.js:20-20 |
| PV-0022 | vuln | A01:2021 | A01:2025 | high | 2 | app_node/controllers/orderController.js:37-37 |
| PV-0023 | vuln | A01:2021 | A01:2025 | high | 4 | app_node/services/roleService.js:11-11 |
| PV-0024 | vuln | A01:2021 | A01:2025 | high | 3 | app_python/doc_service.py:35-35 |
| PV-0025 | vuln | A01:2021 | A01:2025 | high | 3 | app_python/profile_service.py:26-26 |
| PV-0026 | vuln | A01:2021 | A01:2025 | high | 4 | app_node/controllers/invoiceController.js:6-6 |
| PV-0027 | vuln | A01:2021 | A01:2025 | high | 4 | app_python/app.py:182-182 |
| PV-0028 | vuln | A04:2021 | A06:2025 | high | 4 | app_python/tasks/coupon_service.py:40-40 |
| PV-0029 | vuln | A04:2021 | A06:2025 | high | 3 | app_node/controllers/cartController.js:19-19 |
| PV-0030 | vuln | A04:2021 | A06:2025 | high | 4 | app_python/tasks/inventory_service.py:33-33 |
| PV-0031 | vuln | A04:2021 | A06:2025 | high | 4 | app_python/tasks/coupon_service.py:67-67 |
| PV-0032 | vuln | A04:2021 | A06:2025 | high | 4 | app_node/controllers/orderController.js:63-63 |
| PV-0033 | vuln | A04:2021 | A06:2025 | high | 4 | app_python/doc_service.py:55-55 |
| PV-0034 | vuln | A07:2021 | A07:2025 | high | 1 | app_python/config.py:1-1 |
| PV-0035 | vuln | A02:2021 | A04:2025 | high | 1 | app_python/config.py:11-11 |
| PV-0036 | vuln | A02:2021 | A04:2025 | high | 1 | app_python/token_service.py:14-14 |
| PV-0037 | vuln | A05:2021 | A02:2025 | high | 1 | app_python/tasks/export_task.py:20-20 |
| PV-0038 | vuln | A02:2021 | A04:2025 | high | 1 | app_node/services/tokenUtil.js:13-13 |
| PV-0039 | vuln | A02:2021 | A04:2025 | high | 1 | app_python/crypto_util.py:49-49 |
| PV-0040 | vuln | A07:2021 | A07:2025 | high | 2 | app_python/jwt_service.py:20-20 |
| PV-0041 | vuln | A07:2021 | A07:2025 | high | 2 | app_node/controllers/sessionController.js:15-15 |
| PV-0042 | vuln | A02:2021 | A04:2025 | high | 2 | app_python/auth_service.py:43-43 |
| PV-0043 | vuln | A07:2021 | A07:2025 | high | 2 | app_python/auth_service.py:19-19 |
| PV-0044 | vuln | A02:2021 | A04:2025 | high | 1 | app_python/crypto_util.py:27-27 |
| PV-0045 | vuln | A07:2021 | A07:2025 | high | 4 | app_python/auth/mfa_handler.py:22-22 |
| PV-0046 | vuln | A08:2021 | A08:2025 | high | 2 | app_python/yaml_parser.py:18-18 |
| PV-0047 | vuln | A10:2021 | A10:2025 | high | 3 | app_python/tasks/worker.py:10-10 |
| PV-0048 | vuln | A10:2021 | A10:2025 | high | 3 | app_python/ssrf_client.py:18-18 |
| PV-0049 | vuln | A10:2021 | A10:2025 | high | 4 | app_node/services/internalServiceClient.js:14-14 |
| PV-0050 | vuln | A10:2021 | A10:2025 | high | 4 | app_python/app.py:891-891 |
| PV-0051 | vuln | A08:2021 | A08:2025 | high | 4 | app_python/tasks/worker.py:22-22 |
| PV-0052 | vuln | A05:2021 | A02:2025 | high | 1 | app_node/server.js:21-21 |
| PV-0053 | vuln | A06:2021 | A03:2025 | high | 1 | requirements.txt:3-3 |
| PV-0054 | vuln | A06:2021 | A03:2025 | high | 1 | package.json:15-15 |
| PV-0055 | vuln | A05:2021 | A02:2025 | high | 1 | infra/Dockerfile.archive:10-10 |
| PV-0056 | vuln | A05:2021 | A02:2025 | high | 1 | infra/docker-compose.archive.yml:6-6 |
| PV-0057 | vuln | A05:2021 | A02:2025 | high | 1 | app_python/app.py:908-908 |
| PV-0058 | vuln | A05:2021 | A02:2025 | high | 1 | app_node/server.js:29-29 |
| PV-0059 | vuln | A05:2021 | A02:2025 | high | 1 | .env.backup:1-1 |
| PV-0060 | vuln | A05:2021 | A02:2025 | high | 1 | app_node/server.js:70-70 |
| PV-0061 | trap | A03:2021 | A05:2025 | info | 1 | app_node/catalog/resourceController.js:6-6 |
| PV-0062 | trap | A01:2021 | A01:2025 | info | 1 | app_node/catalog/resourceController.js:18-18 |
| PV-0063 | trap | A10:2021 | A10:2025 | info | 3 | app_python/auth_routes.py:24-24 |
| PV-0064 | trap | A01:2021 | A01:2025 | info | 4 | app_node/catalog/resourceController.js:31-31 |
| PV-0065 | trap | A03:2021 | A05:2025 | info | 1 | app_node/catalog/resourceController.js:53-53 |
| PV-0066 | trap | A08:2021 | A08:2025 | info | 4 | app_python/auth_routes.py:98-98 |
| PV-0067 | trap | A03:2021 | A05:2025 | info | 1 | app_node/controllers/searchController.js:50-50 |
| PV-0068 | trap | A03:2021 | A05:2025 | info | 3 | app_node/models/dbClient.js:69-69 |
| PV-0069 | trap | A01:2021 | A01:2025 | info | 3 | app_node/services/roleService.js:37-37 |
| PV-0070 | trap | A01:2021 | A01:2025 | info | 3 | app_python/tasks/worker.py:75-75 |
| PV-0071 | trap | A07:2021 | A07:2025 | info | 1 | app_python/config.py:8-8 |
| PV-0072 | trap | A07:2021 | A07:2025 | info | 3 | app_python/auth/mfa_handler.py:48-48 |
| PV-0073 | trap | A05:2021 | A02:2025 | info | 1 | app_node/server.js:58-58 |
| PV-0074 | trap | A05:2021 | A02:2025 | info | 1 | .env.example:3-3 |
| PV-0075 | trap | A03:2021 | A05:2025 | info | 1 | app_python/app.py:564-564 |
| PV-0076 | trap | A03:2021 | A05:2025 | info | 2 | app_node/controllers/feedbackController.js:30-30 |
| PV-0077 | trap | A05:2021 | A02:2025 | info | 2 | app_python/xml_parser.py:31-31 |
| PV-0078 | trap | A01:2021 | A01:2025 | info | 1 | app_node/controllers/searchController.js:73-73 |
| PV-0079 | trap | A01:2021 | A01:2025 | info | 2 | app_python/doc_service.py:42-42 |
| PV-0080 | trap | A05:2021 | A02:2025 | info | 2 | app_node/controllers/searchController.js:86-86 |
| PV-0081 | trap | A03:2021 | A05:2025 | info | 2 | app_node/controllers/searchController.js:110-110 |
| PV-0082 | trap | A02:2021 | A04:2025 | info | 1 | app_python/token_service.py:24-24 |
| PV-0083 | trap | A01:2021 | A01:2025 | info | 1 | app_python/tasks/export_task.py:25-25 |
| PV-0084 | trap | A07:2021 | A07:2025 | info | 2 | app_python/jwt_service.py:30-30 |
| PV-0085 | trap | A07:2021 | A07:2025 | info | 2 | app_node/controllers/sessionController.js:33-33 |
| PV-0086 | trap | A02:2021 | A04:2025 | info | 1 | app_python/auth_service.py:57-57 |
| PV-0087 | trap | A07:2021 | A07:2025 | info | 2 | app_python/auth_service.py:34-34 |
| PV-0088 | trap | A10:2021 | A10:2025 | info | 3 | app_python/ssrf_client.py:42-42 |
| PV-0089 | trap | A08:2021 | A08:2025 | info | 1 | app_python/yaml_parser.py:22-22 |
| PV-0090 | trap | A03:2021 | A05:2025 | info | 2 | app_node/services/mergeUtil.js:29-29 |
| PV-0091 | trap | A06:2021 | A03:2025 | info | 1 | requirements.txt:4-4 |
| PV-0092 | trap | A06:2021 | A03:2025 | info | 1 | package.json:10-10 |
| PV-0093 | trap | A05:2021 | A02:2025 | info | 1 | infra/Dockerfile.hardened:12-12 |
| PV-0094 | trap | A05:2021 | A02:2025 | info | 1 | infra/docker-compose.hardened.yml:8-8 |
| PV-0095 | trap | A03:2021 | A05:2025 | info | 1 | app_node/controllers/catalogController.js:35-35 |
| PV-0096 | trap | A01:2021 | A01:2025 | info | 2 | app_python/archive_extractor.py:36-36 |
| PV-0097 | trap | A03:2021 | A05:2025 | info | 1 | app_node/controllers/templateController.js:30-30 |
| PV-0098 | trap | A03:2021 | A05:2025 | info | 4 | app_node/services/billingService.js:44-44 |
| PV-0099 | trap | A10:2021 | A10:2025 | info | 4 | app_node/services/internalServiceClient.js:25-25 |
| PV-0100 | trap | A04:2021 | A06:2025 | info | 4 | app_python/tasks/coupon_service.py:53-53 |
| PV-0101 | trap | A04:2021 | A06:2025 | info | 3 | app_node/controllers/cartController.js:49-49 |
| PV-0102 | trap | A04:2021 | A06:2025 | info | 4 | app_python/tasks/inventory_service.py:42-42 |
| PV-0103 | trap | A02:2021 | A04:2025 | info | 1 | app_python/crypto_util.py:35-35 |
| PV-0104 | trap | A02:2021 | A04:2025 | info | 1 | app_node/services/tokenUtil.js:20-20 |
| PV-0105 | trap | A03:2021 | A05:2025 | info | 2 | app_python/diagnostic_service.py:35-35 |
| PV-0106 | trap | A03:2021 | A05:2025 | info | 3 | app_node/controllers/reportController.js:32-32 |
| PV-0107 | trap | A01:2021 | A01:2025 | info | 3 | app_python/profile_service.py:37-37 |
| PV-0108 | trap | A01:2021 | A01:2025 | info | 2 | app_node/controllers/uploadController.js:38-38 |
| PV-0109 | trap | A05:2021 | A02:2025 | info | 1 | app_node/server.js:80-80 |
| PV-0110 | trap | A02:2021 | A04:2025 | info | 1 | app_python/crypto_util.py:54-54 |
| PV-0111 | trap | A05:2021 | A02:2025 | info | 1 | app_python/app.py:897-897 |
| PV-0112 | trap | A01:2021 | A01:2025 | info | 2 | app_node/controllers/orderController.js:50-50 |
| PV-0113 | trap | A03:2021 | A05:2025 | info | 4 | app_python/auth_routes.py:149-149 |
| PV-0114 | trap | A03:2021 | A05:2025 | info | 4 | app_python/auth_routes.py:156-156 |
| PV-0115 | trap | A10:2021 | A10:2025 | info | 4 | app_python/auth_routes.py:161-161 |
| PV-0116 | trap | A07:2021 | A07:2025 | info | 4 | app_node/services/internalServiceClient.js:32-32 |
| PV-0117 | trap | A07:2021 | A07:2025 | info | 4 | app_python/jwt_service.py:30-30 |
| PV-0118 | trap | A04:2021 | A06:2025 | info | 4 | app_python/tasks/coupon_service.py:75-75 |
| PV-0119 | trap | A04:2021 | A06:2025 | info | 4 | app_node/controllers/orderController.js:83-83 |
| PV-0120 | trap | A04:2021 | A06:2025 | info | 4 | app_python/doc_service.py:67-67 |
| PV-0121 | vuln | A09:2021 | A09:2025 | high | 3 | app_node/server.js:209-209 |
| PV-0122 | vuln | A08:2021 | A08:2025 | high | 3 | app_node/server.js:212-212 |
| PV-0123 | vuln | A05:2021 | A02:2025 | critical | 4 | app_node/server.js:215-215 |
| PV-0124 | vuln | A04:2021 | A06:2025 | high | 2 | app_node/server.js:218-218 |
| PV-0125 | vuln | A09:2021 | A09:2025 | high | 3 | app_node/server.js:221-221 |
| PV-0126 | vuln | A01:2021 | A01:2025 | high | 3 | app_node/server.js:224-224 |
| PV-0127 | vuln | A01:2021 | A01:2025 | critical | 4 | app_node/server.js:227-227 |
| PV-0128 | vuln | A08:2021 | A08:2025 | high | 2 | app_node/server.js:230-230 |
| PV-0129 | vuln | A08:2021 | A08:2025 | high | 3 | app_node/server.js:233-233 |
| PV-0130 | vuln | A09:2021 | A09:2025 | high | 3 | app_node/server.js:236-236 |
| PV-0131 | vuln | A09:2021 | A09:2025 | critical | 4 | app_node/server.js:239-239 |
| PV-0132 | vuln | A08:2021 | A08:2025 | high | 2 | app_node/server.js:242-242 |
| PV-0133 | vuln | A04:2021 | A06:2025 | high | 3 | app_node/server.js:245-245 |
| PV-0134 | vuln | A05:2021 | A02:2025 | high | 3 | app_node/server.js:248-248 |
| PV-0135 | vuln | A04:2021 | A06:2025 | critical | 4 | app_node/server.js:251-251 |
| PV-0136 | vuln | A10:2021 | A10:2025 | high | 2 | app_node/server.js:254-254 |
| PV-0137 | vuln | A09:2021 | A09:2025 | high | 3 | app_node/server.js:257-257 |
| PV-0138 | vuln | A03:2021 | A05:2025 | high | 3 | app_node/server.js:260-260 |
| PV-0139 | vuln | A08:2021 | A08:2025 | critical | 4 | app_node/server.js:263-263 |
| PV-0140 | vuln | A01:2021 | A01:2025 | high | 2 | app_node/server.js:266-266 |
| PV-0141 | vuln | A04:2021 | A06:2025 | high | 3 | app_node/server.js:269-269 |
| PV-0142 | vuln | A09:2021 | A09:2025 | high | 3 | app_node/server.js:272-272 |
| PV-0143 | vuln | A05:2021 | A02:2025 | critical | 4 | app_node/server.js:275-275 |
| PV-0144 | vuln | A01:2021 | A01:2025 | high | 2 | app_node/server.js:278-278 |
| PV-0145 | vuln | A08:2021 | A08:2025 | high | 3 | app_node/server.js:281-281 |
| PV-0146 | vuln | A09:2021 | A09:2025 | high | 3 | app_node/server.js:284-284 |
| PV-0147 | vuln | A03:2021 | A05:2025 | critical | 4 | app_node/server.js:287-287 |
| PV-0148 | vuln | A10:2021 | A10:2025 | high | 2 | app_node/server.js:290-290 |
| PV-0149 | vuln | A08:2021 | A08:2025 | high | 3 | app_node/server.js:293-293 |
| PV-0150 | vuln | A06:2021 | A03:2025 | high | 3 | app_node/server.js:296-296 |
| PV-0151 | vuln | A01:2021 | A01:2025 | critical | 4 | app_node/server.js:299-299 |
| PV-0152 | vuln | A01:2021 | A01:2025 | high | 2 | app_node/server.js:302-302 |
| PV-0153 | vuln | A04:2021 | A06:2025 | high | 3 | app_node/server.js:306-306 |
| PV-0154 | vuln | A01:2021 | A01:2025 | high | 3 | app_node/server.js:309-309 |
| PV-0155 | vuln | A01:2021 | A01:2025 | critical | 4 | app_node/server.js:312-312 |
| PV-0156 | vuln | A08:2021 | A08:2025 | high | 2 | app_node/server.js:315-315 |
| PV-0157 | vuln | A09:2021 | A09:2025 | high | 3 | app_node/server.js:318-318 |
| PV-0158 | vuln | A09:2021 | A09:2025 | high | 3 | app_node/server.js:321-321 |
| PV-0159 | vuln | A08:2021 | A08:2025 | critical | 4 | app_node/server.js:324-324 |
| PV-0160 | vuln | A01:2021 | A01:2025 | high | 2 | app_node/server.js:327-327 |
| PV-0161 | trap | A01:2021 | A01:2025 | info | 3 | app_node/server.js:333-333 |
| PV-0162 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:337-337 |
| PV-0163 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:341-341 |
| PV-0164 | trap | A01:2021 | A01:2025 | info | 3 | app_node/server.js:345-345 |
| PV-0165 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:349-349 |
| PV-0166 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:353-353 |
| PV-0167 | trap | A01:2021 | A01:2025 | info | 3 | app_node/server.js:357-357 |
| PV-0168 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:361-361 |
| PV-0169 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:365-365 |
| PV-0170 | trap | A01:2021 | A01:2025 | info | 3 | app_node/server.js:369-369 |
| PV-0171 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:373-373 |
| PV-0172 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:376-376 |
| PV-0173 | trap | A01:2021 | A01:2025 | info | 3 | app_node/server.js:380-380 |
| PV-0174 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:384-384 |
| PV-0175 | trap | A01:2021 | A01:2025 | info | 2 | app_node/server.js:388-388 |
