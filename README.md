# Awesome Honeypots [![Awesome Honeypots](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome honeypots, plus related components and much more, divided into categories such as Web, services, and others, with a focus on free and open source projects.

There is no pre-established order of items in each category, the order is for contribution. If you want to contribute, please read the [guide](CONTRIBUTING.md).

Discover more awesome lists at <b><code>322051⭐</code></b> <b><code>&nbsp;27599🍴</code></b> [sindresorhus/awesome](https://github.com/sindresorhus/awesome)).

# Contents

- [Awesome Honeypots ![Awesome Honeypots](https://github.com/sindresorhus/awesome)](#awesome-honeypots-)
- [Contents](#contents)
  - [Related Lists](#related-lists)
  - [Honeypots](#honeypots)
  - [Honeyd Tools](#honeyd-tools)
  - [Network and Artifact Analysis](#network-and-artifact-analysis)
  - [Data Tools](#data-tools)
  - [Guides](#guides)

## Related Lists

- <b><code>&nbsp;&nbsp;3075⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;465🍴</code></b> [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools)) - Useful in network traffic analysis.
- <b><code>&nbsp;11558⭐</code></b> <b><code>&nbsp;&nbsp;2531🍴</code></b> [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis)) - Some overlap here for artifact analysis.

## Honeypots

- Database Honeypots

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;20⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [Delilah](https://github.com/SecurityTW/delilah)) - Elasticsearch Honeypot written in Python (originally from Novetta).
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [ESPot](https://github.com/mycert/ESPot)) - Elasticsearch honeypot written in NodeJS, to capture every attempts to exploit CVE-2014-3120.
  - 🌎 [ElasticPot](gitlab.com/bontchev/elasticpot) - An Elasticsearch Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;182⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;56🍴</code></b> [Elastic honey](https://github.com/jordan-wright/elastichoney)) - Simple Elasticsearch Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;88⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;23🍴</code></b> [MongoDB-HoneyProxy](https://github.com/Plazmaz/MongoDB-HoneyProxy)) - MongoDB honeypot proxy.
  - <b><code>&nbsp;&nbsp;&nbsp;101⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;23🍴</code></b> [NoSQLpot](https://github.com/torque59/nosqlpot)) - Honeypot framework built on a NoSQL-style database.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;30⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15🍴</code></b> [mysql-honeypotd](https://github.com/sjinks/mysql-honeypotd)) - Low interaction MySQL honeypot written in C.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;20⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [MysqlPot](https://github.com/schmalle/MysqlPot)) - MySQL honeypot, still very early stage.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [pghoney](https://github.com/betheroot/pghoney)) - Low-interaction Postgres Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [sticky_elephant](https://github.com/betheroot/sticky_elephant)) - Medium interaction postgresql honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;16⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [RedisHoneyPot](https://github.com/cypwnpwnsocute/RedisHoneyPot)) - High Interaction Honeypot Solution for Redis protocol.

- Web honeypots

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [Express honeypot](https://github.com/christophe77/express-honeypot)) - RFI & LFI honeypot using nodeJS and express.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;33⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;21🍴</code></b> [EoHoneypotBundle](https://github.com/eymengunay/EoHoneypotBundle)) - Honeypot type for Symfony2 forms.
  - <b><code>&nbsp;&nbsp;&nbsp;551⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;172🍴</code></b> [Glastopf](https://github.com/mushorg/glastopf)) - Web Application Honeypot.
  - [Google Hack Honeypot](http://ghh.sourceforge.net) - Designed to provide reconnaissance against attackers that use search engines as a hacking tool against your resources.
  - <b><code>&nbsp;&nbsp;&nbsp;642⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;33🍴</code></b> [HellPot](https://github.com/yunginnanet/HellPot)) - Honeypot that tries to crash the bots and clients that visit it's location.
  - <b><code>&nbsp;&nbsp;&nbsp;428⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;44🍴</code></b> [Laravel Application Honeypot](https://github.com/msurguy/Honeypot)) - Simple spam prevention package for Laravel applications.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;43⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9🍴</code></b> [Nodepot](https://github.com/schmalle/Nodepot)) - NodeJS web application honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [PasitheaHoneypot](https://github.com/Marist-Innovation-Lab/PasitheaHoneypot)) - RestAPI honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [Servletpot](https://github.com/schmalle/servletpot)) - Web application Honeypot.
  - 🌎 [Shadow Daemon](shadowd.zecure.org/overview/introduction/) - Modular Web Application Firewall / High-Interaction Honeypot for PHP, Perl, and Python apps.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;71⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17🍴</code></b> [StrutsHoneypot](https://github.com/Cymmetria/StrutsHoneypot)) - Struts Apache 2 based honeypot as well as a detection module for Apache 2 servers.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;59⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;16🍴</code></b> [WebTrap](https://github.com/IllusiveNetworks-Labs/WebTrap)) - Designed to create deceptive webpages to deceive and redirect attackers away from real websites.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;46⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [basic-auth-pot (bap)](https://github.com/bjeborn/basic-auth-pot)) - HTTP Basic Authentication honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [bwpot](https://github.com/graneed/bwpot)) - Breakable Web applications honeyPot.
  - <b><code>&nbsp;&nbsp;1009⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;185🍴</code></b> [django-admin-honeypot](https://github.com/dmpayton/django-admin-honeypot)) - Fake Django admin login screen to notify admins of attempted unauthorized access.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;56⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11🍴</code></b> [drupo](https://github.com/d1str0/drupot)) - Drupal Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;370⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;35🍴</code></b> [galah](https://github.com/0x4D31/galah)) - an LLM-powered web honeypot using the OpenAI API.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;41⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;16🍴</code></b> [honeyhttpd](https://github.com/bocajspear1/honeyhttpd)) - Python-based web server honeypot builder.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [honeyup](https://github.com/LogoiLab/honeyup)) - An uploader honeypot designed to look like poor website security.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;52⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [modpot](https://github.com/referefref/modpot)) - Modpot is a modular web application honeypot framework and management application written in Golang and making use of gin framework.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;63⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15🍴</code></b> [owa-honeypot](https://github.com/joda32/owa-honeypot)) - A basic flask based Outlook Web Honey pot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;64⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;35🍴</code></b> [phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot)) - Simple and effective phpMyAdmin honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [shockpot](https://github.com/threatstream/shockpot)) - WebApp Honeypot for detecting Shell Shock exploit attempts.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;16⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [smart-honeypot](https://github.com/freak3dot/smart-honeypot)) - PHP Script demonstrating a smart honey pot.
  - Snare/Tanner - successors to Glastopf
    - <b><code>&nbsp;&nbsp;&nbsp;438⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;135🍴</code></b> [Snare](https://github.com/mushorg/snare)) - Super Next generation Advanced Reactive honeypot.
    - <b><code>&nbsp;&nbsp;&nbsp;219⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;101🍴</code></b> [Tanner](https://github.com/mushorg/tanner)) - Evaluating SNARE events.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [stack-honeypot](https://github.com/CHH/stack-honeypot)) - Inserts a trap for spam bots into responses.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [tomcat-manager-honeypot](https://github.com/helospark/tomcat-manager-honeypot)) - Honeypot that mimics Tomcat manager endpoints. Logs requests and saves attacker's WAR file for later study.
  - WordPress honeypots
    - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;28⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [HonnyPotter](https://github.com/MartinIngesen/HonnyPotter)) - WordPress login honeypot for collection and analysis of failed login attempts.
    - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11🍴</code></b> [HoneyPress](https://github.com/kungfuguapo/HoneyPress)) - Python based WordPress honeypot in a Docker container.
    - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;26⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [wp-smart-honeypot](https://github.com/freak3dot/wp-smart-honeypot)) - WordPress plugin to reduce comment spam with a smarter honeypot.
    - <b><code>&nbsp;&nbsp;&nbsp;176⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;61🍴</code></b> [wordpot](https://github.com/gbrindisi/wordpot)) - WordPress Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;423⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;138🍴</code></b> [Python-Honeypot](https://github.com/OWASP/Python-Honeypot)) - OWASP Honeypot, Automated Deception Framework.

- Service Honeypots
  - <b><code>&nbsp;&nbsp;&nbsp;158⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;33🍴</code></b> [ADBHoney](https://github.com/huuck/ADBHoney)) - Low interaction honeypot that simulates an Android device running Android Debug Bridge (ADB) server process.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;16⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [AMTHoneypot](https://github.com/packetflare/amthoneypot)) - Honeypot for Intel's AMT Firmware Vulnerability CVE-2017-5689.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;41⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11🍴</code></b> [ddospot](https://github.com/aelth/ddospot)) - NTP, DNS, SSDP, Chargen and generic UDP-based amplification DDoS honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;695⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;185🍴</code></b> [dionaea](https://github.com/DinoTools/dionaea)) - Home of the dionaea honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;28⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [dhp](https://github.com/ciscocsirt/dhp)) - Simple Docker Honeypot server emulating small snippets of the Docker HTTP API.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [DolosHoneypot](https://github.com/Marist-Innovation-Lab/DolosHoneypot)) - SDN (software defined networking) honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;65⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;14🍴</code></b> [Ensnare](https://github.com/ahoernecke/ensnare)) - Easy to deploy Ruby honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;35⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [Helix](https://github.com/Zeerg/helix-honeypot)) - K8s API Honeypot with Active Defense Capabilities.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;26⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;14🍴</code></b> [honeycomb_plugins](https://github.com/Cymmetria/honeycomb_plugins)) - Plugin repository for Honeycomb, the honeypot framework by Cymmetria.
  - [honeydb] (https://honeydb.io/downloads) - Multi-service honeypot that is easy to deploy and configure. Can be configured to send interaction data to to HoneyDB's centralized collectors for access via REST API.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;52⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12🍴</code></b> [honeyntp](https://github.com/fygrave/honeyntp)) - NTP logger/honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;51⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;19🍴</code></b> [honeypot-camera](https://github.com/alexbredo/honeypot-camera)) - Observation camera honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;27⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;14🍴</code></b> [honeypot-ftp](https://github.com/alexbredo/honeypot-ftp)) - FTP Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;648⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;109🍴</code></b> [honeypots](https://github.com/qeeqbox/honeypots)) - 25 different honeypots in a single pypi package! (dns, ftp, httpproxy, http, https, imap, mysql, pop3, postgres, redis, smb, smtp, socks5, ssh, telnet, vnc, mssql, elastic, ldap, ntp, memcache, snmp, oracle, sip and irc).
  - <b><code>&nbsp;&nbsp;1213⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;176🍴</code></b> [honeytrap](https://github.com/honeytrap/honeytrap)) - Advanced Honeypot framework written in Go that can be connected with other honeypot software.
  - <b><code>&nbsp;&nbsp;&nbsp;457⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;94🍴</code></b> [HoneyPy](https://github.com/foospidy/HoneyPy)) - Low interaction honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;19⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [Honeygrove](https://github.com/UHH-ISS/honeygrove)) - Multi-purpose modular honeypot based on Twisted.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;41⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [Honeyport](https://github.com/securitygeneration/Honeyport)) - Simple honeyport written in Bash and Python.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;19⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11🍴</code></b> [Honeyprint](https://github.com/glaslos/honeyprint)) - Printer honeypot.
  - 🌎 [Lyrebird](hub.docker.com/r/lyrebird/honeypot-base/) - Modern high-interaction honeypot framework.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;14⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [MICROS honeypot](https://github.com/Cymmetria/micros_honeypot)) - Low interaction honeypot to detect CVE-2018-2636 in the Oracle Hospitality Simphony component of Oracle Hospitality Applications (MICROS).
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [node-ftp-honeypot](https://github.com/christophe77/node-ftp-honeypot)) - FTP server honeypot in JS.
  - <b><code>&nbsp;&nbsp;1483⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;242🍴</code></b> [pyrdp](https://github.com/gosecure/pyrdp)) - RDP man-in-the-middle and library for Python 3 with the ability to watch connections live or after the fact.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;61⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11🍴</code></b> [rdppot](https://github.com/kryptoslogic/rdppot)) - RDP honeypot
  - <b><code>&nbsp;&nbsp;1675⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;545🍴</code></b> [RDPy](https://github.com/citronneur/rdpy)) - Microsoft Remote Desktop Protocol (RDP) honeypot implemented in Python.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;46⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17🍴</code></b> [SMB Honeypot](https://github.com/r0hi7/HoneySMB)) - High interaction SMB service honeypot capable of capturing wannacry-like Malware.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [Tom's Honeypot](https://github.com/inguardians/toms_honeypot)) - Low interaction Python honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;21⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [Trapster Commmunity](https://github.com/0xBallpoint/trapster-community)) - Modural and easy to install Python Honeypot, with comprehensive alerting
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [troje](https://github.com/dutchcoders/troje/)) - Honeypot that runs each connection with the service within a separate LXC container.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;31⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12🍴</code></b> [WebLogic honeypot](https://github.com/Cymmetria/weblogic_honeypot)) - Low interaction honeypot to detect CVE-2017-10271 in the Oracle WebLogic Server component of Oracle Fusion Middleware.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [WhiteFace Honeypot](https://github.com/csirtgadgets/csirtg-honeypot)) - Twisted based honeypot for WhiteFace.
 
- Distributed Honeypots

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;58⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12🍴</code></b> [DemonHunter](https://github.com/RevengeComing/DemonHunter)) - Low interaction honeypot server.

- Anti-honeypot stuff

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;13⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [canarytokendetector](https://github.com/referefref/canarytokendetector)) - Tool for detection and nullification of Thinkst CanaryTokens
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;71⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [honeydet](https://github.com/referefref/honeydet)) - Signature based honeypot detector tool written in Golang
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;55⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12🍴</code></b> [kippo_detect](https://github.com/andrew-morris/kippo_detect)) - Offensive component that detects the presence of the kippo honeypot.

- ICS/SCADA honeypots

  - <b><code>&nbsp;&nbsp;1221⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;413🍴</code></b> [Conpot](https://github.com/mushorg/conpot)) - ICS/SCADA honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;131⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;35🍴</code></b> [GasPot](https://github.com/sjhilt/GasPot)) - Veeder Root Gaurdian AST, common in the oil and gas industry.
  - [SCADA honeynet](http://scadahoneynet.sourceforge.net) - Building Honeypots for Industrial Networks.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;54⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;13🍴</code></b> [gridpot](https://github.com/sk4ld/gridpot)) - Open source tools for realistic-behaving electric grid honeynets.
  - [scada-honeynet](http://www.digitalbond.com/blog/2007/07/24/scada-honeynet-article-in-infragard-publication/) - Mimics many of the services from a popular PLC and better helps SCADA researchers understand potential risks of exposed control system devices.

- Other/random

  - <b><code>&nbsp;&nbsp;&nbsp;113⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;29🍴</code></b> [CitrixHoneypot](https://github.com/MalwareTech/CitrixHoneypot)) - Detect and log CVE-2019-19781 scan and exploitation attempts.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [Damn Simple Honeypot (DSHP)](https://github.com/naorlivne/dshp)) - Honeypot framework with pluggable handlers.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [dicompot](https://github.com/nsmfoo/dicompot)) - DICOM Honeypot.
  - 🌎 [IPP Honey](gitlab.com/bontchev/ipphoney) - A honeypot for the Internet Printing Protocol.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;89⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;27🍴</code></b> [Log4Pot](https://github.com/thomaspatzke/Log4Pot)) - A honeypot for the Log4Shell vulnerability (CVE-2021-44228).
  - <b><code>&nbsp;&nbsp;&nbsp;100⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15🍴</code></b> [Masscanned](https://github.com/ivre/masscanned)) - Let's be scanned. A low-interaction honeypot focused on network scanners and bots. It integrates very well with IVRE to build a self-hosted alternative to GreyNoise.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;21⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [medpot](https://github.com/schmalle/medpot)) -  HL7 / FHIR honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;73⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22🍴</code></b> [NOVA](https://github.com/DataSoft/Nova)) - Uses honeypots as detectors, looks like a complete system.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [OpenFlow Honeypot (OFPot)](https://github.com/upa/ofpot)) - Redirects traffic for unused IPs to a honeypot, built on POX.
  - <b><code>&nbsp;&nbsp;2270⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;355🍴</code></b> [OpenCanary](https://github.com/thinkst/opencanary)) - Modular and decentralised honeypot daemon that runs several canary versions of services that alerts when a service is (ab)used.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;49⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22🍴</code></b> [ciscoasa_honeypot](https://github.com/cymmetria/ciscoasa_honeypot)) A low interaction honeypot for the Cisco ASA component capable of detecting CVE-2018-0101, a DoS and remote code execution vulnerability.
  - <b><code>&nbsp;&nbsp;&nbsp;198⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;18🍴</code></b> [miniprint](https://github.com/sa7mon/miniprint)) - A medium interaction printer honeypot.

- Botnet C2 tools

  - <b><code>&nbsp;&nbsp;&nbsp;183⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;64🍴</code></b> [Hale](https://github.com/pjlantz/Hale)) - Botnet command and control monitor.
  - 🌎 [dnsMole](code.google.com/archive/p/dns-mole/) - Analyses DNS traffic and potentionaly detect botnet command and control server activity, along with infected hosts.

- IPv6 attack detection tool

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [ipv6-attack-detector](https://github.com/mzweilin/ipv6-attack-detector/)) - Google Summer of Code 2012 project, supported by The Honeynet Project organization.

- Dynamic code instrumentation toolkit

  - 🌎 [Frida](www.frida.re) - Inject JavaScript to explore native apps on Windows, Mac, Linux, iOS and Android.

- Tool to convert website to server honeypots

  - [HIHAT](http://hihat.sourceforge.net/) - Transform arbitrary PHP applications into web-based high-interaction Honeypots.

- Malware collector

  - 🌎 [Kippo-Malware](bruteforcelab.com/kippo-malware) - Python script that will download all malicious files stored as URLs in a Kippo SSH honeypot database.

- Distributed sensor deployment

  - 🌎 [Community Honey Network](communityhoneynetwork.readthedocs.io/en/stable/) - CHN aims to make deployments honeypots and honeypot management tools easy and flexible. The default deployment method uses Docker Compose and Docker to deploy with a few simple commands.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Modern Honey Network](https://github.com/threatstream/mhn)) - Multi-snort and honeypot sensor management, uses a network of VMs, small footprint SNORT installations, stealthy dionaeas, and a centralized server for management.

- Network Analysis Tool

  - 🌎 [Tracexploit](code.google.com/archive/p/tracexploit/) - Replay network packets.

- Log anonymizer

  - [LogAnon](http://code.google.com/archive/p/loganon/) - Log anonymization library that helps having anonymous logs consistent between logs and network captures.

- Low interaction honeypot (router back door)

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [Honeypot-32764](https://github.com/knalli/honeypot-for-tcp-32764)) - Honeypot for router backdoor (TCP 32764).
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [WAPot](https://github.com/lcashdol/WAPot)) - Honeypot that can be used to observe traffic directed at home routers.

- honeynet farm traffic redirector

  - 🌎 [Honeymole](web.archive.org/web/20100326040550/http://www.honeynet.org.pt:80/index.php/HoneyMole) - Deploy multiple sensors that redirect traffic to a centralized collection of honeypots.

- HTTPS Proxy

  - 🌎 [mitmproxy](mitmproxy.org/) - Allows traffic flows to be intercepted, inspected, modified, and replayed.

- System instrumentation

  - 🌎 [Sysdig](sysdig.com/opensource/) - Open source, system-level exploration allows one to capture system state and activity from a running GNU/Linux instance, then save, filter, and analyze the results.
  - <b><code>&nbsp;&nbsp;2129⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;182🍴</code></b> [Fibratus](https://github.com/rabbitstack/fibratus)) - Tool for exploration and tracing of the Windows kernel.

- Honeypot for USB-spreading malware

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;93⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;26🍴</code></b> [Ghost-usb](https://github.com/honeynet/ghost-usb-honeypot)) - Honeypot for malware that propagates via USB storage devices.

- Data Collection

  - 🌎 [Kippo2MySQL](bruteforcelab.com/kippo2mysql) - Extracts some very basic stats from Kippo’s text-based log files and inserts them in a MySQL database.
  - 🌎 [Kippo2ElasticSearch](bruteforcelab.com/kippo2elasticsearch) - Python script to transfer data from a Kippo SSH honeypot MySQL database to an ElasticSearch instance (server or cluster).

- Passive network audit framework parser

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;31⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9🍴</code></b> [Passive Network Audit Framework (pnaf)](https://github.com/jusafing/pnaf)) - Framework that combines multiple passive and automated analysis techniques in order to provide a security assessment of network platforms.

- VM monitoring and tools

  - <b><code>&nbsp;&nbsp;&nbsp;711⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;123🍴</code></b> [Antivmdetect](https://github.com/nsmfoo/antivmdetection)) - Script to create templates to use with VirtualBox to make VM detection harder.
  - <b><code>&nbsp;&nbsp;&nbsp;479⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;118🍴</code></b> [VMCloak](https://github.com/hatching/vmcloak)) - Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox.
  - [vmitools](http://libvmi.com/) - C library with Python bindings that makes it easy to monitor the low-level details of a running virtual machine.

- Binary debugger

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;31⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [Hexgolems - Pint Debugger Backend](https://github.com/hexgolems/pint)) - Debugger backend and LUA wrapper for PIN.
  - <b><code>&nbsp;&nbsp;&nbsp;141⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15🍴</code></b> [Hexgolems - Schem Debugger Frontend](https://github.com/hexgolems/schem)) - Debugger frontend.

- Mobile Analysis Tool

  - <b><code>&nbsp;&nbsp;5182⭐</code></b> <b><code>&nbsp;&nbsp;1055🍴</code></b> [Androguard](https://github.com/androguard/androguard)) - Reverse engineering, Malware and goodware analysis of Android applications and more.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [APKinspector](https://github.com/honeynet/apkinspector/)) - Powerful GUI tool for analysts to analyze the Android applications.

- Low interaction honeypot

  - 🌎 [Honeyperl](sourceforge.net/projects/honeyperl/) - Honeypot software based in Perl with plugins developed for many functions like : wingates, telnet, squid, smtp, etc.
  - <b><code>&nbsp;&nbsp;6601⭐</code></b> <b><code>&nbsp;&nbsp;1061🍴</code></b> [T-Pot](https://github.com/dtag-dev-sec/tpotce)) - All in one honeypot appliance from telecom provider T-Mobile
  - <b><code>&nbsp;&nbsp;&nbsp;642⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;49🍴</code></b> [beelzebub](https://github.com/mariocandela/beelzebub)) - A secure honeypot framework, extremely easy to configure by yaml 🚀

- Honeynet data fusion

  - 🌎 [HFlow2](projects.honeynet.org/hflow) - Data coalesing tool for honeynet/network analysis.

- Server

  - [Amun](http://amunhoney.sourceforge.net) - Vulnerability emulation honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Artillery](https://github.com/trustedsec/artillery/)) - Open-source blue team tool designed to protect Linux and Windows operating systems through multiple methods.
  - [Bait and Switch](http://baitnswitch.sourceforge.net) - Redirects all hostile traffic to a honeypot that is partially mirroring your production system.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [Bifrozt](https://github.com/Ziemeck/bifrozt-ansible)) - Automatic deploy bifrozt with ansible.
  - [Conpot](http://conpot.org/) - Low interactive server side Industrial Control Systems honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;371⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;79🍴</code></b> [Heralding](https://github.com/johnnykv/heralding)) - Credentials catching honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;20⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [HoneyWRT](https://github.com/CanadianJeff/honeywrt)) - Low interaction Python honeypot designed to mimic services or ports that might get targeted by attackers.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [Honeyd](https://github.com/provos/honeyd)) - See [honeyd tools](#honeyd-tools).
  - [Honeysink](http://www.honeynet.org/node/773) - Open source network sinkhole that provides a mechanism for detection and prevention of malicious traffic on a given network.
  - <b><code>&nbsp;&nbsp;&nbsp;158⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;48🍴</code></b> [Hontel](https://github.com/stamparm/hontel)) - Telnet Honeypot.
  - [KFSensor](http://www.keyfocus.net/kfsensor/) - Windows based honeypot Intrusion Detection System (IDS).
  - [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - Takes over unused IP addresses, and creates virtual servers that are attractive to worms, hackers, and other denizens of the Internet.
  - <b><code>&nbsp;&nbsp;&nbsp;103⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;34🍴</code></b> [MTPot](https://github.com/Cymmetria/MTPot)) - Open Source Telnet Honeypot, focused on Mirai malware.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [SIREN](https://github.com/blaverick62/SIREN)) - Semi-Intelligent HoneyPot Network - HoneyNet Intelligent Virtual Environment.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [TelnetHoney](https://github.com/balte/TelnetHoney)) - Simple telnet honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;47⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10🍴</code></b> [UDPot Honeypot](https://github.com/jekil/UDPot)) - Simple UDP/DNS honeypot scripts.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [Yet Another Fake Honeypot (YAFH)](https://github.com/fnzv/YAFH)) - Simple honeypot written in Go.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [arctic-swallow](https://github.com/ajackal/arctic-swallow)) - Low interaction honeypot.
  - <b><code>&nbsp;&nbsp;1510⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;177🍴</code></b> [fapro](https://github.com/fofapro/fapro)) - Fake Protocol Server.
  - <b><code>&nbsp;&nbsp;&nbsp;241⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;57🍴</code></b> [glutton](https://github.com/mushorg/glutton)) - All eating honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;42⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [go-HoneyPot](https://github.com/Mojachieee/go-HoneyPot)) - Honeypot server written in Go.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [go-emulators](https://github.com/kingtuna/go-emulators)) - Honeypot Golang emulators.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;27⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [honeymail](https://github.com/sec51/honeymail)) - SMTP honeypot written in Golang.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;92⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;18🍴</code></b> [honeytrap](https://github.com/tillmannw/honeytrap)) - Low-interaction honeypot and network security tool written to catch attacks against TCP and UDP services.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;24⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [imap-honey](https://github.com/yvesago/imap-honey)) - IMAP honeypot written in Golang.
  - 🌎 [mwcollectd](www.openhub.net/p/mwcollectd) - Versatile malware collection daemon, uniting the best features of nepenthes and honeytrap.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;28⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [potd](https://github.com/lnslbrty/potd)) - Highly scalable low- to medium-interaction SSH/TCP honeypot designed for OpenWrt/IoT devices leveraging several Linux kernel features, such as namespaces, seccomp and thread capabilities.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;30⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [portlurker](https://github.com/bartnv/portlurker)) - Port listener in Rust with protocol guessing and safe string display.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;16⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [slipm-honeypot](https://github.com/rshipp/slipm-honeypot)) - Simple low-interaction port monitoring honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;303⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;87🍴</code></b> [telnet-iot-honeypot](https://github.com/Phype/telnet-iot-honeypot)) - Python telnet honeypot for catching botnet binaries.
  - <b><code>&nbsp;&nbsp;&nbsp;236⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;62🍴</code></b> [telnetlogger](https://github.com/robertdavidgraham/telnetlogger)) - Telnet honeypot designed to track the Mirai botnet.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [vnclowpot](https://github.com/magisterquis/vnclowpot)) - Low interaction VNC honeypot.

- IDS signature generation

  - [Honeycomb](http://www.icir.org/christian/honeycomb/) - Automated signature creation using honeypots.

- Lookup service for AS-numbers and prefixes

  - [CC2ASN](http://www.cc2asn.com/) - Simple lookup service for AS-numbers and prefixes belonging to any given country in the world.

- Data Collection / Data Sharing

  - [HPfriends](http://hpfriends.honeycloud.net/#/home) - Honeypot data-sharing platform.
    - 🌎 [hpfriends - real-time social data-sharing](heipei.io/sigint-hpfriends/) - Presentation about HPFriends feed system
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [HPFeeds](https://github.com/rep/hpfeeds/)) - Lightweight authenticated publish-subscribe protocol.

- Central management tool

  - [PHARM](http://www.nepenthespharm.com/) - Manage, report, and analyze your distributed Nepenthes instances.

- Network connection analyzer

  - [Impost](http://impost.sourceforge.net/) - Network security auditing tool designed to analyze the forensics behind compromised and/or vulnerable daemons.

- Honeypot deployment

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [honeyfs](https://github.com/referefref/honeyfs)) - Tool to create artificial file systems for medium/high interaction honeypots.
  - [Modern Honeynet Network](http://threatstream.github.io/mhn/) - Streamlines deployment and management of secure honeypots.

- Honeypot extensions to Wireshark

  - 🌎 [Wireshark Extensions](www.honeynet.org/project/WiresharkExtensions) - Apply Snort IDS rules and signatures against packet capture files using Wireshark.

- Client

  - 🌎 [CWSandbox / GFI Sandbox](www.gfi.com/products-and-solutions/all-products)
  - 🌎 [Capture-HPC-Linux](redmine.honeynet.org/projects/linux-capture-hpc/wiki)
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10🍴</code></b> [Capture-HPC-NG](https://github.com/CERT-Polska/HSN-Capture-HPC-NG))
  - 🌎 [Capture-HPC](projects.honeynet.org/capture-hpc) - High interaction client honeypot (also called honeyclient).
  - [HoneyBOT](http://www.atomicsoftwaresolutions.com/)
  - 🌎 [HoneyC](projects.honeynet.org/honeyc)
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;28⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9🍴</code></b> [HoneySpider Network](https://github.com/CERT-Polska/hsn2-bundle)) - Highly-scalable system integrating multiple client honeypots to detect malicious websites.
  - 🌎 [HoneyWeb](code.google.com/archive/p/gsoc-honeyweb/) - Web interface created to manage and remotely share Honeyclients resources.
  - <b><code>&nbsp;&nbsp;&nbsp;160⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;65🍴</code></b> [Jsunpack-n](https://github.com/urule99/jsunpack-n))
  - [MonkeySpider](http://monkeyspider.sourceforge.net)
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;24⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9🍴</code></b> [PhoneyC](https://github.com/honeynet/phoneyc)) - Python honeyclient (later replaced by Thug).
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Pwnypot](https://github.com/shjalayeri/pwnypot)) - High Interaction Client Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Rumal](https://github.com/thugs-rumal/)) - Thug's Rumāl: a Thug's dress and weapon.
  - 🌎 [Shelia](www.cs.vu.nl/~herbertb/misc/shelia/) - Client-side honeypot for attack detection.
  - 🌎 [Thug](buffer.github.io/thug/) - Python-based low-interaction honeyclient.
  - 🌎 [Thug Distributed Task Queuing](thug-distributed.readthedocs.io/en/latest/index.html)
  - 🌎 [Trigona](www.honeynet.org/project/Trigona)
  - 🌎 [URLQuery](urlquery.net/)
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;68⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10🍴</code></b> [YALIH (Yet Another Low Interaction Honeyclient)](https://github.com/Masood-M/yalih)) - Low-interaction client honeypot designed to detect malicious websites through signature, anomaly, and pattern matching techniques.

- Honeypot

  - [Deception Toolkit](http://www.all.net/dtk/dtk.html)
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [IMHoneypot](https://github.com/mushorg/imhoneypot))

- PDF document inspector

  - <b><code>&nbsp;&nbsp;1278⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;240🍴</code></b> [peepdf](https://github.com/jesparza/peepdf)) - Powerful Python tool to analyze PDF documents.

- Hybrid low/high interaction honeypot

  - [HoneyBrid](http://honeybrid.sourceforge.net)

- SSH Honeypots

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;18⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [Blacknet](https://github.com/morian/blacknet)) - Multi-head SSH honeypot system.
  - <b><code>&nbsp;&nbsp;5091⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;871🍴</code></b> [Cowrie](https://github.com/cowrie/cowrie)) - Cowrie SSH Honeypot (based on kippo).
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;14⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [DShield docker](https://github.com/xme/dshield-docker)) - Docker container running cowrie with DShield output enabled.
  - <b><code>&nbsp;&nbsp;7113⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;271🍴</code></b> [endlessh](https://github.com/skeeto/endlessh)) - SSH tarpit that slowly sends an endless banner.  🌎 [docker image](hub.docker.com/r/linuxserver/endlessh))
  - <b><code>&nbsp;&nbsp;&nbsp;372⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;73🍴</code></b> [HonSSH](https://github.com/tnich/honssh)) - Logs all SSH communications between a client and server.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [HUDINX](https://github.com/Cryptix720/HUDINX)) - Tiny interaction SSH honeypot engineered in Python to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
  - <b><code>&nbsp;&nbsp;1605⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;280🍴</code></b> [Kippo](https://github.com/desaster/kippo)) - Medium interaction SSH honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [Kippo_JunOS](https://github.com/gregcmartin/Kippo_JunOS)) - Kippo configured to be a backdoored netscreen.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;37⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [Kojoney2](https://github.com/madirish/kojoney2)) - Low interaction SSH honeypot written in Python and based on Kojoney by Jose Antonio Coret.
  - [Kojoney](http://kojoney.sourceforge.net/) - Python-based Low interaction honeypot that emulates an SSH server implemented with Twisted Conch.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [Longitudinal Analysis of SSH Cowrie Honeypot Logs](https://github.com/deroux/longitudinal-analysis-cowrie)) - Python based command line tool to analyze cowrie logs over time.
  - [LongTail Log Analysis @ Marist College](http://longtail.it.marist.edu/honey/) - Analyzed SSH honeypot logs.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [Malbait](https://github.com/batchmcnulty/Malbait)) - Simple TCP/UDP honeypot implemented in Perl.
  - <b><code>&nbsp;&nbsp;&nbsp;124⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;23🍴</code></b> [MockSSH](https://github.com/ncouture/MockSSH)) - Mock an SSH server and define all commands it supports (Python, Twisted).
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [cowrie2neo](https://github.com/xlfe/cowrie2neo)) - Parse cowrie honeypot logs into a neo4j database.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;31⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [go-sshoney](https://github.com/ashmckenzie/go-sshoney)) - SSH Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;34⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [go0r](https://github.com/fzerorubigd/go0r)) - Simple ssh honeypot in Golang.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [gohoney](https://github.com/PaulMaddox/gohoney)) - SSH honeypot written in Go.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [hived](https://github.com/sahilm/hived)) - Golang-based honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;37⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12🍴</code></b> [hnypots-agent)](https://github.com/joshrendek/hnypots-agent)) - SSH Server in Go that logs username and password combinations.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;27⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [honeypot.go](https://github.com/mdp/honeypot.go)) - SSH Honeypot written in Go.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [honeyssh](https://github.com/ppacher/honeyssh)) - Credential dumping SSH honeypot with statistics.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;21⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [hornet](https://github.com/czardoz/hornet)) - Medium interaction SSH honeypot that supports multiple virtual hosts.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [ssh-auth-logger](https://github.com/JustinAzoff/ssh-auth-logger)) - Low/zero interaction SSH authentication logging honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;614⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;240🍴</code></b> [ssh-honeypot](https://github.com/droberson/ssh-honeypot)) - Fake sshd that logs IP addresses, usernames, and passwords.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [ssh-honeypot](https://github.com/amv42/sshd-honeypot)) - Modified version of the OpenSSH deamon that forwards commands to Cowrie where all commands are interpreted and returned.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;13⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [ssh-honeypotd](https://github.com/sjinks/ssh-honeypotd)) - Low-interaction SSH honeypot written in C.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;38⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [sshForShits](https://github.com/traetox/sshForShits)) - Framework for a high interaction SSH honeypot.
  - <b><code>&nbsp;&nbsp;1492⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;88🍴</code></b> [sshesame](https://github.com/jaksi/sshesame)) - Fake SSH server that lets everyone in and logs their activity.
  - <b><code>&nbsp;&nbsp;&nbsp;167⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;53🍴</code></b> [sshhipot](https://github.com/magisterquis/sshhipot)) - High-interaction MitM SSH honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [sshlowpot](https://github.com/magisterquis/sshlowpot)) - Yet another no-frills low-interaction SSH honeypot in Go.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;95⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9🍴</code></b> [sshsyrup](https://github.com/mkishere/sshsyrup)) - Simple SSH Honeypot with features to capture terminal activity and upload to asciinema.org.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;84⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;20🍴</code></b> [twisted-honeypots](https://github.com/lanjelot/twisted-honeypots)) - SSH, FTP and Telnet honeypots based on Twisted.

- Distributed sensor project

  - 🌎 [DShield Web Honeypot Project](sites.google.com/site/webhoneypotsite/)

- A pcap analyzer

  - 🌎 [Honeysnap](projects.honeynet.org/honeysnap/)

- Network traffic redirector

  - 🌎 [Honeywall](projects.honeynet.org/honeywall/)

- Honeypot Distribution with mixed content

  - 🌎 [HoneyDrive](bruteforcelab.com/honeydrive)

- Honeypot sensor

  - 🌎 [Honeeepi](redmine.honeynet.org/projects/honeeepi/wiki) - Honeypot sensor on a Raspberry Pi based on a customized Raspbian OS.

- File carving

  - 🌎 [TestDisk & PhotoRec](www.cgsecurity.org/)

- Behavioral analysis tool for win32

  - 🌎 [Capture BAT](www.honeynet.org/node/315)

- Live CD

  - 🌎 [DAVIX](www.secviz.org/node/89) - The DAVIX Live CD.

- Spamtrap

  - 🌎 [Mail::SMTP::Honeypot](metacpan.org/pod/release/MIKER/Mail-SMTP-Honeypot-0.11/Honeypot.pm) - Perl module that appears to provide the functionality of a standard SMTP server.
  - <b><code>&nbsp;&nbsp;&nbsp;248⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;71🍴</code></b> [Mailoney](https://github.com/awhitehatter/mailoney)) - SMTP honeypot, Open Relay, Cred Harvester written in python.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [SendMeSpamIDS.py](https://github.com/johestephan/VerySimpleHoneypot)) - Simple SMTP fetch all IDS and analyzer.
  - <b><code>&nbsp;&nbsp;&nbsp;131⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;36🍴</code></b> [Shiva](https://github.com/shiva-spampot/shiva)) - Spam Honeypot with Intelligent Virtual Analyzer.
    - 🌎 [Shiva The Spam Honeypot Tips And Tricks For Getting It Up And Running](www.pentestpartners.com/security-blog/shiva-the-spam-honeypot-tips-and-tricks-for-getting-it-up-and-running/)
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [SMTPLLMPot](https://github.com/referefref/SMTPLLMPot)) - A super simple SMTP Honeypot built using GPT3.5
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [SpamHAT](https://github.com/miguelraulb/spamhat)) - Spam Honeypot Tool.
  - [Spamhole](http://www.spamhole.net/)
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [honeypot](https://github.com/jadb/honeypot)) - The Project Honey Pot un-official PHP SDK.
  - [spamd](http://man.openbsd.org/cgi-bin/man.cgi?query=spamd%26apropos=0%26sektion=0%26manpath=OpenBSD+Current%26arch=i386%26format=html)

- Commercial honeynet

  - [Cymmetria Mazerunner](ttps://cymmetria.com/products/mazerunner/) - Leads attackers away from real targets and creates a footprint of the attack.

- Server (Bluetooth)

  - <b><code>&nbsp;&nbsp;&nbsp;233⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;29🍴</code></b> [Bluepot](https://github.com/andrewmichaelsmith/bluepot))

- Dynamic analysis of Android apps

  - 🌎 [Droidbox](code.google.com/archive/p/droidbox/)

- Dockerized Low Interaction packaging

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;21⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [Docker honeynet](https://github.com/sreinhardt/Docker-Honeynet)) - Several Honeynet tools set up for Docker containers.
  - 🌎 [Dockerized Thug](hub.docker.com/r/honeynet/thug/) - Dockerized <b><code>&nbsp;&nbsp;&nbsp;977⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;204🍴</code></b> [Thug](https://github.com/buffer/thug)) to analyze malicious web content.
  - <b><code>&nbsp;&nbsp;&nbsp;147⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;14🍴</code></b> [Dockerpot](https://github.com/mrschyte/dockerpot)) - Docker based honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [Manuka](https://github.com/andrewmichaelsmith/manuka)) - Docker based honeypot (Dionaea and Kippo).
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [honey_ports](https://github.com/run41/honey_ports)) - Very simple but effective docker deployed honeypot to detect port scanning in your environment.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;32⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [mhn-core-docker](https://github.com/MattCarothers/mhn-core-docker)) - Core elements of the Modern Honey Network implemented in Docker.

- Network analysis

  - 🌎 [Quechua](bitbucket.org/zaccone/quechua)

- SIP Server

  - [Artemnesia VoIP](http://artemisa.sourceforge.net)

- SIP

  - <b><code>&nbsp;&nbsp;&nbsp;153⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17🍴</code></b> [SentryPeer](https://github.com/SentryPeer/SentryPeer)) - Protect your SIP Servers from bad actors.

- IOT Honeypot

  - <b><code>&nbsp;&nbsp;&nbsp;121⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;43🍴</code></b> [HoneyThing](https://github.com/omererdem/honeything)) - TR-069 Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;24⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [Kako](https://github.com/darkarnium/kako)) - Honeypots for a number of well known and deployed embedded device vulnerabilities.

- Honeytokens
  - <b><code>&nbsp;&nbsp;1724⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;253🍴</code></b> [CanaryTokens](https://github.com/thinkst/canarytokens)) - Self-hostable honeytoken generator and reporting dashboard; demo version available at 🌎 [CanaryTokens.org](canarytokens.org/generate).
  - <b><code>&nbsp;&nbsp;&nbsp;272⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;45🍴</code></b> [Honeybits](https://github.com/0x4D31/honeybits)) - Simple tool designed to enhance the effectiveness of your traps by spreading breadcrumbs and honeytokens across your production servers and workstations to lure the attacker toward your honeypots.
  - <b><code>&nbsp;&nbsp;&nbsp;508⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;52🍴</code></b> [Honeyλ (HoneyLambda)](https://github.com/0x4D31/honeylambda)) - Simple, serverless application designed to create and monitor URL honeytokens, on top of AWS Lambda and Amazon API Gateway.
  - <b><code>&nbsp;&nbsp;&nbsp;498⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;108🍴</code></b> [dcept](https://github.com/secureworks/dcept)) - Tool for deploying and detecting use of Active Directory honeytokens.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;58⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10🍴</code></b> [honeyku](https://github.com/0x4D31/honeyku)) - Heroku-based web honeypot that can be used to create and monitor fake HTTP endpoints (i.e. honeytokens).

## Honeyd Tools

- Honeyd plugin

  - [Honeycomb](http://www.honeyd.org/tools.php)

- Honeyd viewer

  - [Honeyview](http://honeyview.sourceforge.net/)

- Honeyd to MySQL connector

  - 🌎 [Honeyd2MySQL](bruteforcelab.com/honeyd2mysql)

- A script to visualize statistics from honeyd

  - 🌎 [Honeyd-Viz](bruteforcelab.com/honeyd-viz)

- Honeyd stats
  - <b><code>&nbsp;&nbsp;&nbsp;342⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;100🍴</code></b> [Honeydsum.pl](https://github.com/DataSoft/Honeyd/blob/master/scripts/misc/honeydsum-v0.3/honeydsum.pl))

## Network and Artifact Analysis

- Sandbox

  - [Argos](http://www.few.vu.nl/argos/) - Emulator for capturing zero-day attacks.
  - 🌎 [COMODO automated sandbox](help.comodo.com/topic-72-1-451-4768-.html)
  - 🌎 [Cuckoo](cuckoosandbox.org/) - Leading open source automated malware analysis system.
  - <b><code>&nbsp;&nbsp;&nbsp;124⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;31🍴</code></b> [Pylibemu](https://github.com/buffer/pylibemu)) - Libemu Cython wrapper.
  - 🌎 [RFISandbox](monkey.org/~jose/software/rfi-sandbox/) - PHP 5.x script sandbox built on top of 🌎 [funcall](pecl.php.net/package/funcall).
  - <b><code>&nbsp;&nbsp;&nbsp;196⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;35🍴</code></b> [dorothy2](https://github.com/m4rco-/dorothy2)) - Malware/botnet analysis framework written in Ruby.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [imalse](https://github.com/hbhzwj/imalse)) - Integrated MALware Simulator and Emulator.
  - <b><code>&nbsp;&nbsp;&nbsp;138⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;47🍴</code></b> [libemu](https://github.com/buffer/libemu)) - Shellcode emulation library, useful for shellcode detection.

- Sandbox-as-a-Service

  - 🌎 [Hybrid Analysis](www.hybrid-analysis.com) - Free malware analysis service powered by Payload Security that detects and analyzes unknown threats using a unique Hybrid Analysis technology.
  - 🌎 [Joebox Cloud](jbxcloud.joesecurity.org/login) - Analyzes the behavior of malicious files including PEs, PDFs, DOCs, PPTs, XLSs, APKs, URLs and MachOs on Windows, Android and Mac OS X for suspicious activities.
  - 🌎 [VirusTotal](www.virustotal.com/) - Analyze suspicious files and URLs to detect types of malware, and automatically share them with the security community.
  - 🌎 [malwr.com](malwr.com/) - Free malware analysis service and community.

## Data Tools

- Front Ends

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;65⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;27🍴</code></b> [DionaeaFR](https://github.com/rubenespadas/DionaeaFR)) - Front Web to Dionaea low-interaction honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [Django-kippo](https://github.com/jedie/django-kippo)) - Django App for kippo SSH Honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [Shockpot-Frontend](https://github.com/GovCERT-CZ/Shockpot-Frontend)) - Full featured script to visualize statistics from a Shockpot honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;252⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;43🍴</code></b> [Tango](https://github.com/aplura/Tango)) - Honeypot Intelligence with Splunk.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [Wordpot-Frontend](https://github.com/GovCERT-CZ/Wordpot-Frontend)) - Full featured script to visualize statistics from a Wordpot honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [honeyalarmg2](https://github.com/schmalle/honeyalarmg2)) - Simplified UI for showing honeypot alarms.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [honeypotDisplay](https://github.com/Joss-Steward/honeypotDisplay)) - Flask website which displays data gathered from an SSH Honeypot.

- Visualization

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [Acapulco](https://github.com/hgascon/acapulco)) - Automated Attack Community Graph Construction.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;14⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [Afterglow Cloud](https://github.com/ayrus/afterglow-cloud))
  - [Afterglow](http://afterglow.sourceforge.net/)
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [Glastopf Analytics](https://github.com/katkad/Glastopf-Analytics)) - Easy honeypot statistics.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [HoneyMalt](https://github.com/SneakersInc/HoneyMalt)) - Maltego tranforms for mapping Honeypot systems.
  - <b><code>&nbsp;&nbsp;&nbsp;217⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;88🍴</code></b> [HoneyMap](https://github.com/fw42/honeymap)) - Real-time websocket stream of GPS events on a fancy SVG world map.
  - 🌎 [HoneyStats](sourceforge.net/projects/honeystats/) - Statistical view of the recorded activity on a Honeynet.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;14⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [HpfeedsHoneyGraph](https://github.com/yuchincheng/HpfeedsHoneyGraph)) - Visualization app to visualize hpfeeds logs.
  - <b><code>&nbsp;&nbsp;3415⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;632🍴</code></b> [IVRE](https://github.com/ivre/ivre)) - Network recon framework, published by @cea-sec & @ANSSI-FR. Build your own, self-hosted and fully-controlled alternatives to Criminalip / Shodan / ZoomEye / Censys and GreyNoise, run your Passive DNS service, collect and analyse network intelligence from your sensors, and much more!
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [Kippo stats](https://github.com/mfontani/kippo-stats)) - Mojolicious app to display statistics for your kippo SSH honeypot.
  - 🌎 [Kippo-Graph](bruteforcelab.com/kippo-graph) - Full featured script to visualize statistics from a Kippo SSH honeypot.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;61⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;11🍴</code></b> [The Intelligent HoneyNet](https://github.com/jpyorre/IntelligentHoneyNet)) - Create actionable information from honeypots.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;47⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;15🍴</code></b> [ovizart](https://github.com/oguzy/ovizart)) - Visual analysis for network traffic.

## Guides

- 🌎 [T-Pot: A Multi-Honeypot Platform](dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html)
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Honeypot (Dionaea and kippo) setup script](https://github.com/andrewmichaelsmith/honeypot-setup-script/))

- Deployment

  - [Dionaea and EC2 in 20 Minutes](http://andrewmichaelsmith.com/2012/03/dionaea-honeypot-on-ec2-in-20-minutes/) - Tutorial on setting up Dionaea on an EC2 instance.
  - 🌎 [Using a Raspberry Pi honeypot to contribute data to DShield/ISC](isc.sans.edu/diary/22680) - The Raspberry Pi based system will allow us to maintain one code base that will make it easier to collect rich logs beyond firewall logs.
  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;32⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [honeypotpi](https://github.com/free5ty1e/honeypotpi)) - Script for turning a Raspberry Pi into a HoneyPot Pi.

- Research Papers

  - <b><code>&nbsp;&nbsp;&nbsp;&nbsp;27⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [Honeypot research papers](https://github.com/shbhmsingh72/Honeypot-Research-Papers)) - PDFs of research papers on honeypots.
  - 🌎 [vEYE](link.springer.com/article/10.1007%2Fs10115-008-0137-3) - Behavioral footprinting for self-propagating worm detection and profiling.

## Source
<b><code>&nbsp;&nbsp;8395⭐</code></b> <b><code>&nbsp;&nbsp;1242🍴</code></b> [paralax/awesome-honeypots](https://github.com/paralax/awesome-honeypots))