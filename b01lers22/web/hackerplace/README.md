# hacker/place

Categories: Web

Description:
> After the smash success of r/place, hackers have opened hacker/place for their own groups to duke it out on. However, some script kiddies managed to steal the secret key and place pixels much faster than all of us. It's your job to hack the hackers and even the playing field.
> 
> http://ctf.b01lers.com:9401/
> 
> Author: DJ
> Difficulty: Medium

**Tags:** WebSockets, WebMessages, JWT tokens

## Takeaways

## Solution

Upon vising the website we are presented with the following page.

![index.png](writeup-resources/index.png)

It's a webpage where you can draw stuff. However, you are limited to drawing only 1 pixel every 10 seconds. The challenge is accompanied with source code so let's dive into it.

### Overview

It is a client-server application. The client clicks on the screen and a message is send to the server about what `x`,`y`,`color` the client drew on. The canvas is shared among clients. So when the server receives a change, it broadcasts it to all its connected clients.

### Goal

The goal here is to leak the `secret` variable. This will allow us to modify the JWT token, include an `"admin": 1` field, and then visit `/flag` to get the flag.

### Intuition

The first part is to understand what the code does. So let's take a look at `index.js`, i.e. the client-side code.

```javascript
let canvas = document.querySelector('canvas');
let ws = new WebSocket(`ws://${location.hostname}:${location.port}/`);
ws.onmessage = async function (e) {
    let palette = document.getElementsByClassName('color')
    let data = new Uint8Array(await e.data.arrayBuffer());
    switch (data[0]) {  //data[0] acts like a command opcode
        case 1:
            //Draw canvas received by server
            for (let y = 0; y < canvas.height; y++) {
                for (let x = 0; x < canvas.width; x++) {
                    ctx.fillStyle = palette[data[y * 400 + x + 1]].id;
                    ctx.fillRect(x, y, 1, 1);
                }
            }
            break;
        case 2:
            //Draw 1 pixel
            let str = String.fromCharCode.apply(null, data);
            let x = JSON.parse(str.slice(1, 4));
            let y = JSON.parse(str.slice(4, 7));
            ctx.fillStyle = JSON.parse(str.slice(7));
            ctx.fillRect(x, y, 1, 1);
            break;
        case 3:
            //Draw "Cooldown" box
            cooldownDiv.style.display = 'block';
            let cooldown = 10;
            cooldownCounter.innerText = String(cooldown);
            let interval = setInterval(() => {
                cooldown--;
                cooldownCounter.innerText = String(cooldown);
                if (cooldown <= 0) {
                    cooldownDiv.style.display = 'none';
                    clearInterval(interval);
                }
            }, 1000);
            break;
    }
};

canvas.onclick = function (e) {
    let coords = project(e.offsetX, e.offsetY);
    let packet = '';
    packet += leftPad(String(coords[0]), ' ', 3);
    packet += leftPad(String(coords[1]), ' ', 3);
    packet += '"' + paletteElem.id + '"';
    ws.send(packet);
};
```

Now we have a solid idea about what the client receives from and sends to the server. Let's also take a look server-side.

```javascript

const secret = 'seeeeecret';

app.use((req, res, next) => {
    if ('token' in req.cookies) {
        try {
            let token = jwt.verify(req.cookies.token, secret, { algorithms: ['HS256'] });
            req.token = token;
            next();
        } catch (err) { return res.sendStatus(401); }
    } else {
        let token = { cooldown: 10 };
        req.token = token;
        let expires = new Date();
        expires.setFullYear(expires.getFullYear() + 1);
        res.cookie('token', jwt.sign(token, secret, { algorithm: 'HS256' }), {
            expires,
            httpOnly: true,
            sameSite: 'strict',
        });
        next();
    }
});

function setPixel(x, y, color, ws, cooldown) {
    console.log(`setting pixel at ${x},${y} to ${color}`);
    try {
        let packet = Buffer.alloc(7 + color.length);
        packet.writeUInt8(4, 0);
        packet.write(x, 1);
        packet.write(y, 4);
        packet.write(color, 7);
        placers[JSON.parse(x)][JSON.parse(y)].send(packet);
    } catch (err) { }
    try {
        x = JSON.parse(x);
        y = JSON.parse(y);
        if (x > 0 && x < 400 && y > 0 && y < 400 && palette.indexOf(JSON.parse(color)) != -1) {
            if (!('lastPixelPlacedTime' in ws) || Date.now() - ws.lastPixelPlacedTime > cooldown * 1000) {
                ws.lastPixelPlacedTime = Date.now();
                canvas[y * 400 + x] = palette.indexOf(JSON.parse(color));
                let packet = Buffer.alloc(7 + color.length);
                packet.writeUInt8(2, 0);
                packet.write(leftPad(String(x), ' ', 3), 1);
                packet.write(leftPad(String(y), ' ', 3), 4);
                packet.write(color, 7);
                for (let c of clients) {
                    c.send(packet);
                }
                return true;
            }
        }
    } catch (err) {
        console.error(err);
    }
    return false;
}

let clients = [];
let placers = Array(400).fill(Array(400).fill(null))

app.ws('/', (ws, req) => {
    clients.push(ws);
    ws.on('message', (data) => {
        try {
            let str = data.toString();
            let x = str.slice(0, 3);
            let y = str.slice(3, 6);
            let color = str.slice(6);
            if (setPixel(x, y, color, ws, req.token.cooldown)) {
                placers[JSON.parse(x)][JSON.parse(y)] = ws;
                ws.send(Buffer.from([3]));
            }
        } catch (err) { console.error(err); }
    });
    ws.on('close', () => { /* Remove ws client from clients list */ });
});
```

As we can see, the server keeps track of all clients connected to it via the `clients` variable. Each pixel at every `x`, `y` position is also owned by a WebSocket, i.e. another player. When the server receives a message, it sends a message with `data[0] == 4` to the player owning the pixel and it also broadcasts a message `data[0] == 2`. The former message, we didn't see it getting parsed client-side yet, but the latter message serves to notify all clients about the canvas change.

We also see the format of the JWT token and that all players have a cooldown of 10 seconds, i.e. they may draw 1 pixel every 10 seconds.

Not here comes the `bot` player with the following code associated:

```javascript
const jwt = require('jsonwebtoken');
const axios = require('axios');

let canvas = document.querySelector('canvas');
/* Initialize canvas */

let secret = 'seeeeecret';
axios.defaults.baseURL = `http://place:3000/stats/`;
axios.defaults.headers.common['Secret'] = secret;
let cooldown = 1;

function fixImage() { /* Send WebMessages via `conn` to draw a static image */ }

let conn = new WebSocket('ws://place:3000/', {
    headers: {
        'Cookie': `token=${jwt.sign({ cooldown }, secret, { algorithm: 'HS256' })}`
    }
});
conn.onopen = function () {
    console.log('Bot connected to hacker/place');
    setInterval(fixImage, cooldown * 1050);
};

conn.on('message', function (data) {
    let type = data.readUint8();
    switch (type) {
        case 1:
            //Same as client-side, but make changes on a local canvas
            break;
        case 2:
            //Same as client-side, but make changes on a local canvas
            break;
        case 3:
            //no-op
            break;
        case 4:
            try {
                let str = data.toString();
                let x = JSON.parse(str.slice(1, 4));
                let y = JSON.parse(str.slice(4, 7));
                let color = JSON.parse(str.slice(7));
                try {
                    color = color.replace('://', '')    //filtering
                } catch (err) { }

                console.log(`Logging opposing pixel placed at ${x}, ${y} with color ${color}`);
                axios(color, {
                    method: 'post',
                    data: { x, y }
                }).catch((err) => {});
            } catch (err) { console.error('error'); }
            break;
    }
});
```

As you can see, the bot player knows the secret that we want to leak. It abuses it to draw faster than other players, i.e. 1 pixel every 1 second instead of 10 seconds (cheater!). It is also implementing the case `data[0] == 4`.

As you can see, when the bot receives the message with `data[0] == 4`, it makes the following request:

```javascript
axios(color, {
    method: 'post',
    data: { x, y }
}).catch((err) => {});
```

This is a POST request to the `color` URL. However, the `color` comes from the server message, which in-turn comes from another player's message when the player overwrites the bot's drawing! So the `color` variable is tainted. A player can affect the URL to which the bot will make a request. And the bot includes the `Secret` header with the `secret` value in all its requests as seen by `axios.defaults.headers.common['Secret'] = secret`.

So, let's overwrite one of the bot's pixels with our own pixel and use a URL as a color. This is how a regular client -> server message looks like when we use the `black` color at `(x,y) = (196,152)`.

![to-server-reg.png](writeup-resources/to-server-reg.png)

So, we just replace the color with a URL:

![to-server-mal.png](writeup-resources/to-server-mal.png)

We use `http://q908xuw4f7knrxw5amife5lz3q9gx5.burpcollaborator.net` as our malicious URL. Note that in the payload we have repeated the sequence `://` twice. This is to bypass the simple `color = color.replace('://', '')` filter that the bot has. This filter only replaces the first occurrence of the pattern but not the second (or any remaining in general). So, we send the above payload and then check our malicious server for activity.

![callback-success.png](writeup-resources/callback-success.png)

As we can see, we successfully leaked the secret from the bot! Now, let's modify the JWT token in order to become admin and get the flag.

![jwt.png](writeup-resources/jwt.png)

So, we set our cookie `token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb29sZG93biI6MTAsImlhdCI6MTY1MDgzMDUwNiwiYWRtaW4iOjF9.TwZFaC-UWp4CWKefmFgti4rCycvsf7Lwy9cEHe2wqLM`, visit `/flag` and then we are presented with the flag!

`bctf{pl4y_n1ce_w1th_th3_0ther_h4ck3rz_d34r}`
