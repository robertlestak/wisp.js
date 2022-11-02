FROM golang:1.18

WORKDIR /src

COPY . .
RUN go build -o /bin/server cmd/server/*.go

COPY ./static /static

RUN GOOS=js GOARCH=wasm go build -o /static/main.wasm cmd/wasm/main.go && \
    cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" /static/wasm_exec.js && \
    cp /static/wisp.js /static/wisp.js.stub && \
    mv /static/wasm_exec.js /static/wisp.js && \
    cat /static/wisp.js.stub >> /static/wisp.js && \
    rm /static/wisp.js.stub

ENV STATIC_DIR /static

ENTRYPOINT [ "/bin/server" ]