Script parce RDP ntlm chalenge and SSL certificate

Run:
rdp.py host port

Example:
python3 rdp.py 10.10.20.128 3389

Example of output:

Remote Desktop Protocol:
  Имя сервера       : TEST
  Имя домена        : DEMO
  FQDN сервера      : test.demo.lab
  FQDN домена       : demo.lab
  Родительский домен: demo.lab
  Версия OS         : 10.0.17763
  OS                : Windows 10/Server 2019 (Build 17763)

Сертификат сервера:
  Кем выдан         : CN=test.demo.lab
  Кому выдан        : CN=test.demo.lab
  Действителен      : с 24.11.2024 11:10:10 по 26.05.2025 11:10:10
  Серийный номер    : 24999975379612382816970869492084299803
  Версия            : X.509v3
  Алгоритм подписи  : sha256WithRSAEncryption
