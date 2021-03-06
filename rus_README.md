**MOI (Mail/Message over IPFS)** - Система бессерверного обмена файлами/сообщениями, работающая поверх IPFS.

##### Прицип работы:

Клиентские ноды содержат на /ipns/ точке питоновский словарь в пикл формате следующей структуры:

```
structure = 
{
'Public_encryption': 'public Alice key for encoding', 
'Public_signing': 'public Alice key for signing', 
'Message': 
	{'message_id_hash': #message_id_5383710b780583f1f462b6e719071523147cde25a5a47c380126c3395f84b9b3
	{'Address': address,  #e6jB08WPeBjoPS4Lb4CFRVW.....w6GLWYkY2vjhCgtux5vUuE+sKC97yMd9X9xhf5V8=
    'Files': ['Qm...', 'Qm...', 'Qm...']}},
    #... and other messages
'Points': []
}
```
**'Public_encryption'** - публичный ключ ECDH Curve25519 используемый для шифрования AES ключа, которым зашифрованы все вложенные файлы.

**'Public_signing'** - публичный ключ ECDSA Curve P-256, используемый для проверки подписи файлов в сообшениях.

**'Message'** 
-- ключ, в который входит всё, относящееся к сообщениям.

**'message_id_hash'** - ключ и идентификатор сообщения, служащий для того, чтобы отделять одни сообщения от других. В данном примере это “message_id_” скомпанованный с sha256 случайных байтов. Ключ включает в себя всё, связанное с конкретным сообщением

**'Address'** - Идентификатор, позволяющий адресату определить, что сообщение адресовано ему. Не даёт внешнему наблюдателю определить адресата. Схема получения адреса - шифрование_публичным_ключом_адресата(nonce, публичный ключ адресата или его часть)

**'Files'** - список всех файлов сообщения, включая текстовые, представленных в виде мультихэшей сети IPFS. Файл представляет собой питоновский словарь в формате пикл со структурой ключей 
_['Key', 'Nonce', 'Ciphertext', 'Tag', 'Signature']_

**'Key'** - AES ключ, зашифрованный 'Public_encryption' ключом отправителя (возможно добавление идентификатора, говорящего о том, зашифрован ли ключ или нет <вероятно лучше его ставить в метаданных>)

**'Nonce'** - случайная последовательность, служащая для улучшения шифрования

**'Ciphertext'** - зашифрованный файл

**'Tag'** - специальный тэг, позволяющий определить аутентичность данных, зашифрованных предпологаемым ключом AES

**'Signature'** - криптографическая подпись, которой можно проверить аутентичность авторства при помощи 'Public_signing' ключа

Помимо этого внутри 'message_id_hash' ключа предполагается место для метаданных.
Таким образом структурированы и остальные сообщения, расположенные в ключе 'Message'

**'Points'** - обновляемый список IPNS нод, служащий для улучшения связности нодовой сети.


Предполагается для удобства пользователя сделать некое подобие ростера, где публичному ключу шифрования (и по возможности подписи) будет соответствовать ник. Помимо прочего, возможно использование нескольких ключей, а также адресов, при незнании публичного ключа пользователя (в таком случае надо иметь ввиду, что сообщение необходимо будет посылать в открытом виде) 

___________________________________________________

##### MVP
MVP будет представлять собой консольное приложение, поддерживающее следующие команды:

_**init**_ - первичная инициирование нового пользователя, генерация пар ключей. После этой процедуры у пользователя запрашивается пароль для генерации AES ключа для шифрования секретных ключей (и, возможно, бд, ростера, етц). Вероятнее всего все данные пользователя, включая ключи, настройки и ростер будут храниться в одном файле, для простоты переноса. В дальнейшем планируется возможность генерации ключей из парольной фразы.
 
_**roster-add ‘instance‘ ‘username’**_ - назначить публичному ключу или адресу ник (а также возможно будет поддерживаться стягивание публичных ключей при подаче ipns ноды) 

_**check level=1**_ - инициация процедуры проверки наличия новых сообщений (характеристика количества проверяемых ipns нод или глубину проверяемых нод задаётся в файле конфигурации. В результате выдаётся нумерованный список из ников и новых сообщений (айди сообщений хранятся в бд и сравниваются). Пользователь может ввести номер сообщения, которое его интересует или выбрать все. После выбора создаётся папка с ником автора сообщения (если нету), а внутри неё - папка с айди сообщения, куда и скачиваются расшифрованные файлы.
<возможен другой формат представления - ник или адрес и количество сообщений, пользователь выбирает что он хочет посмотреть дальше и ему выдаётся  список новых сообщений выбранного пользователя>

_**send ‘folder’ ‘destination’**_- производит сообщение из файлов в указанной папке и «отсылает» его указанному пользователю (можно в виде ника, публичного ключа или адреса). В последнем случае пользователю выдаётся предупреждение, что сообщение не будет зашифровано публичным ключом.

_**mop all/address**_ - удаление всех папок с сообщениями от всех пользователей

_**export-pub enc/sign**_ - показывает публичный ключ для кодирования в hex формате / публичный ключ для проверки подписи в PEM формате

_**export-sec enc/sign**_ - показывает секретный ключ для кодирования в hex формате / секретный ключ для подписи в PEM формате. Перед показом пользователю выводится сообщение о секретности этой информации и просят ввести пароль.

_**roster-export**_ - экспортирует ростер в файл

_**roster-import**_ - импортирует ростер из файла (дополняя имеющийся)

_**roster-delete nick/pubkey/address**_ - удалить из ростера ник, публичный ключ или адрес

_**roster-show nick/pub_key**_ - показать всё, ассоциированное с ником или ник по адресу.

_**import-sec enc/sign**_ - даёт возможность импортировать ключевую пару взамен существующей (возможно автоматически делается бэкап с запросом пароля) _<нужно ли?>_

_**wipe**_ - удаление всего профиля пользователя, ключая ключи, базы данных, файлы сообщений и т.д.

_**make-address nick/pub_key**_ - сгенерировать адрес для ника или конкретного публичного адреса

И др.
___________________________________________________

На деле нужно только init, send, check, wipe, mop, make address, roster-add, roster-delete, roster-show.

**init** принцип работы:

* Проверка наличия профиля. Если есть, то спросить, хочет ли пользователь действительно стереть старый (возможность бэкапа). Если нет профиля, то далее.

* Спросить пользователя какой из вариантов генерации ему подходит:

*ECC:* 

генерация пар из своего пароля.

генерация пароля для пользователя и генерация пар из него.

генерация случайных пар (необходимо физически сохранять файл с бд для переноса айдентити)

*AES:*

генерация ключа из пароля (желательно иного, чем при генерации пар ключей)

генерация рандомного ключа и сохранение его как файла на диск

* Запостить стандартный node_dic с данными пользователя на ipns
* Создать ростер с бутстрап-нодами
* Создать конфиг со счётчиком использованных пар ключей, настройками глубины проверки check и т.п.



