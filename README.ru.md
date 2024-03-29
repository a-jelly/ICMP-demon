# ICMP-demon - сервис port-knockig-а на базе анализа ping-пакетов.

## Описание
Если вы системный администратор, то вероятно устали от просмотра логов, которые забиты бесконечными попытками ботов залогиниться на ваш сервер по SSH, и хотели бы раз и навсегда избавиться от них. Данный сервис реализует известную технику "выстукивания портов" но не на базе анализа обращения к различным портам, а на путем проверки содержимого входящих ping (ICMP) пакетов. При одинаковой скрытности, эта техника дает некоторые преимущества в удобстве использования за счет того, что доступна практически с любого клиента будь то Linux, Windows, Mac и даже мобильный телефон под Android. Она не требует от удаленного администратора иметь никаких дополнительных инструментов кроме утилиты ping. ICMP-демон работающий на стороне сервера анализирет содержимое приходящих ICMP-пакетов и выполняет действия, описанные в файле конфигурации. Например, запус или остановка сервисов, открытие и закрытие определенных портов в linux firewall.

### Как это работает?

ICMP-демон прослушивает RAW-socket на сервере, и анализирует содержимое приходящих ping пакетов. Если содержимое совпадает с одним из тех, что описано в файле конфигурации и адрес, с которого пришли пакеты входит в список разрещенных, демон запускает скрипт, заданный в файле конфигурации. Имеется защита от повторного запуска (т.к. по умолчанию ping генерирует больше чем один пакет). 


## Пример использования
Пусть у нас уже создан файл конфигурации - config.toml, тогда для запуска достаточно выдать команду:
```
sudo ./icmp_demon -c config.toml
```
Права суперпользователя необходимы демону для прослушивания raw socket.


## Инсталляция из исходников

Скачайте исходные тексты с github-repo, установите GCC и GNU make.
```
git clone https://github.com/a-jelly/ICMP-demon
cd ICMP-demon
make
make install
```    
Команда make install установит в каталог /usr/lib/systemd/system файл описания сервиса ICMP-demon, а сам демон в /usr/local/sbin
Файл конфигурации в этом случае нужно поместить в /etc/icmp_demon/config.toml

## Конфигурация

Вот пример конфигурационного файла:

```
# Пример TOML-based конфигурации
[log]
    use_syslog = 1      # Использовать системный лог.

[network]
    # bind_interface = "eth0"
    # bind_address = "192.168.1.1"
    only_from = ["192.168.1.0/24", "192.168.2.0/24"]
    repeat_timeout = -1   	# ICMP sequence 1 only
    # repeat_timeout = 5  	# 5 sec. timeout for host
    ping_type = "all"	 	# values: raw, 32bit, 64bit, all

[script.open]
    user = "root"
    group = "root"
    # content = "0pen_my_SSH"
    hex_content = "cafebabe"
    path = "/usr/local/sbin/ssh_port_open.sh"  # script to open SSH port

[script.close]
    user = "root"
    group = "root"
    # content = "Cl0se_my_SSH"
    hex_content = "deadface"
    path = "/usr/local/sbin/ssh_port_close.sh" # script to close SSH port
    
```

Несколько опций нуждаются в пояснении. Для защиты от повторного выполнения действия (скажем, если администратор забудет указать число попыток в ping) имеется две возможности:
- задать таймаут в секундах, в течении которого пакеты с этого адреса будут игнорироваться.
- задать repeat_timeout = -1, в этом случае демон примет во внимание только первый пакет в ICMP sequence.

Вторая интересная опция это ping_type. Она указывает, какие виды пакетов анализировать. Из-за особенностей реализации, ICMP-пакет в 32-х и 64-х битных системах имеет разный формат (разную длину timestamp). Демон может реагировать на каждый из них. Также есть специальные утилиты типа nping, которые позволяют поместить в поле data в ICMP-пакет любые данные. Если вы хотите воспринимать такие пакеты - используйте опцию "raw". Если же вы хотите анализировать пакеты всех трех типов - используёте опцию "all".
	
Секция скриптов описывает каждый отдельный скрипт, запускаемый демоном в случае совпадения контента в пакете с тем, что описан в конфигурации скрипта. Контен может задаваться в двух формах - hex_content - в шестнадцатеричной форме (под утилиту ping) и в строковой (если вы хотите использовать nping. Из-за особенностей реализации ping длина hex-content должна быть кратна 4-м байтам (8 шестнадцатеричных цифр) - иначе совпадения не произойдет. Остальные поля самоочевидны: это пользователь и группа от имени которых запускается скрипт и путь к нему.
	
## Использование с удаленого хоста.
Предположим, ваша конфигурация такая, как указано в файле конфигурации и вы хотите доступиться к серверу по SSH (по умолчанию порты SSH закрыты). Тогда достаточно выдать команду:
```
ping -c2 -p cafebabe my.server.ip
```
Далее можно выдать команду:
```
ssh my.server.ip
```
После окончания сеанса следует закрыть порт SSH:
```
ping -c2 -p deadface my.server.ip
```

## Опции командной строки

В командной строке доступны следующие опции:
```
	-c <cfg file>                     - указание файла конфигурации
	-v {error|warning|info|debug}     - задать уровень логирования событий
	-d                                - запуск в режиме с отсоединенным терминалом
	-h                                - показать help
```

## Запуск и остановка сервиса

Для запуска в foreground используйте команду:
```
sudo ./icmp_demon -c config.toml
```

Для запуска в режиме сервиса systemd используйте:
```
systemctl enable icmp-demon
systemctl start icmp-demon
```   
Для остановки сервиса выдайте:
```
systemctl stop icmp-demon
```   
   Будьте осторожны, при неправильной конфигурации или если вы остановите сервис забыв включить SSH, вы можете потерять удаленный доступ к серверу. 
   
## Контакт
Andrew Jelly - ajelly at gmail.com   
