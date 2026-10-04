# prebuilt/ 放「没有 Go 工具链的部署机」用的静态二进制（8MB，不入库）：
#   prebuilt/index = CGO_ENABLED=0 go build 出来的 www-apps/go UDS sidecar
# 由 www-apps/go/init.sh 在 go 缺失时安装到 deps/bin/index。
