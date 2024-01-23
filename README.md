# Go HTTP File Server

## 简介

Go HTTP File Server 是一个基于 Go 语言的简易 HTTP 服务器，用于处理文件的上传、下载和删除操作。它支持通过 HTTP 请求来进行文件操作，并提供基本的密钥认证功能。

## 功能

- 文件上传
- 文件下载
- 文件删除
- 基于密钥的请求认证

## 安装

要安装和运行此服务器，你需要先在你的机器上安装 Go。可以从 Go 官方网站 下载。

安装 Go 后，克隆仓库到本地:

```shell
git clone https://github.com/bluegitter/go-http-fileserver.git
cd go-http-fileserver
```

## 配置

在运行服务器之前，你可以通过命令行参数来指定监听端口和密钥。如果不指定密钥，系统将生成一个随机密钥。

## 运行

使用以下命令来启动服务器：

```shell
go run fileserver.go -p [端口号] -sk [密钥]
```

如果省略 `-p` 和 `-sk` 参数，服务器将默认监听在 8080 端口，并生成一个随机密钥。

例如：

```shell
go run fileserver.go -p 8080 -sk yourSecretKey
```

## 使用

一旦服务器运行起来，你可以通过以下 `curl` 命令与之交互：

- 上传文件：

  ```shell
  curl -X PUT -F file=@/path/to/your/file http://localhost:8080/bucket-name/object-name -H "X-Secret-Key: yourSecretKey"
  ```

- 下载文件：

  ```shell
  curl -o local-filename http://localhost:8080/bucket-name/object-name -H "X-Secret-Key: yourSecretKey"
  ```

- 删除文件：

  ```shell
  curl -X DELETE http://localhost:8080/bucket-name/object-name -H "X-Secret-Key: yourSecretKey"
  ```

## 安全性

请注意，这个服务器是一个简单的示例实现，不应在生产环境中使用。特别是其安全性可能不足以处理敏感数据。

## 贡献

我们欢迎任何形式的贡献。请通过 GitHub issues 或者拉取请求来提交问题或改进。

## 许可

MIT License

<!--  -->
