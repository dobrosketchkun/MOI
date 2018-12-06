- Сделать два формата адресов. Теперь, когда пользователь из одного мастер-пароля может генерировать сколько захочет пар ключей, можно спокойно использовать публичные ключ как адрес, который генерирует пользователь для повышения конфеденциальности.
Внешний же пользователь, если не хочет в открытую ассоциироваться с неким публичным ключом адресата, может сгенерировать адрес следующим образом: ```публичный_ключ_алисы( нонс, [паб_алисы_или_его_часть, публичный_боба])```. Таким образом _Алиса_ спокойно сможет связаться с _Бобом_, имея и его адрес и возможность зашифровки сообщения. 

На самом деле чуть сложнее - из-за специфики curve25519 необходимо знать публичный адрес человека, который шифровал, чтобы потом расшифровать сообщение. Чтобы обойти и не показывать свой истиный публичный ключ можно сгенерировать одноразовую пару ключей и ключ будет формата ```одноразовый_публичный_@_бокс(публичный_алисы, секретный одноразовый)(нонс, [паб_алисы_или_его_часть, публичный_боба]) ```

- Посмотреть возможность генерации пары ключей для IPFS. Насколько я понимаю там используется 2048 RSA, таким образом тоже можно попытаться использовать мастер-ключ pbkdf2. Это поможет переносить ipns между устройствами, что, возможно, поможет связности (?)

- Возможно ввести спецметаметку "Всем" (с возможностью отключения чтения подобных писем в конфиге)

- Сделать поддержку CLI

- Объединить всё наконец в одну рабочую программу