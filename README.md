# nginx Forward 筆記



如果你要用nginx作為WebSocket的前端的話，你可以參考這邊的設定

```
        location /bbs {
                proxy_pass https://localhost:8899;
                proxy_set_header   Upgrade $http_upgrade;
                proxy_set_header Connection "Upgrade";
                proxy_cache_bypass $http_upgrade;
                proxy_set_header   Host $host;
                proxy_set_header Sec-WebSocket-Protocol $http_sec_websocket_protocol;
                proxy_set_header Forwarded "$proxy_forwarded;proto=$scheme;secret=123";
        }

```


```
map $remote_addr $proxy_forwarded {
# IPv4 addresses can be sent as-is
        ~^[0-9.]+$          "for=$remote_addr:$remote_port";

# IPv6 addresses need to be bracketed and quoted
        ~^[0-9A-Fa-f:.]+$   "for=\"[$remote_addr]:$remote_port\"";

# Unix domain socket names cannot be represented in RFC 7239 syntax
        default             "for=unknown";
}
```

這樣就可以讓nginx把IP資訊轉進來了