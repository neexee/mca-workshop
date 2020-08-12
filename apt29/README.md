# What it is
The project contains a playbook for [Math Center Workshop](http://wiki.inhuawei.com/display/CSW/Math+Center+Workshop).

# История
Группа злоумышленников под названием [APT29](https://attack.mitre.org/groups/G0016/) взломала управляющий комитет демократической партии США в 2015 году. Нам достались логи взломанных систем, по ним мы сможем понять, как именно злоумышленники пробрались внутрь, как там скрывались и что они смогли забрать. zip-архивы с логами можно скачать и почитать из [этого репозитория](https://github.com/hunters-forge/mordor/tree/master/datasets/large/apt29).

Шаги атаки можно найти в этих логах глазами (если хочется читать гигабайты событий) или своей программой (если хочется попрограммировать на чём-то своём). Этот репозиторий предлагает воспользоваться Jupyter Notebook-ами, Python-ом и Spark SQL. Про них подробно написано дальше.

# Настройка окружения
1. [Установить Docker](https://docs.docker.com/get-docker/), в нём мы поднимем базу данных, в которую загрузим логи. Если под Windows встретится [проблема](https://github.com/docker/for-win/issues/6651), помогает вот [этот совет](https://social.technet.microsoft.com/Forums/en-US/ee5b1d6b-09e2-49f3-a52c-820aafc316f9/hyperv-doesnt-work-after-upgrade-to-windows-10-1809?forum=win10itprovirt).
2. Установить Git.
3. Пройти [все шаги](https://notebooks-forge.readthedocs.io/en/latest/docker.html#steps) от notebook-forge.
4. Сделать так, чтобы в http://127.0.0.1:8888/jupyter/lab был открыт и работал apt29.ipynb.

![apt29.ipynb](last_step_env.png)

# Задание №1
Найти какую-нибудь технику, тактику или процедуру ATT&CK в логах. Добавить её описание и код для её нахождения в плейбук. Создать pull-request в этом репозитории.

# Ресурсы (где начать копать)
* [MITRE ATT&CK](https://attack.mitre.org/wiki/Main_Page)
* [Detecting Lateral Movement through Tracking Event Logs](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf)
* [Seek Evil, and Ye Shall Find: A Guide to Cyber Threat Hunting Operations](https://digitalguardian.com/blog/seek-evil-and-ye-shall-find-guide-cyber-threat-hunting-operations)
