#!/bin/bash

# AdGuardHome 私人定制安全版 - 构建发布脚本
# 用法: ./scripts/build-release-simple.sh [版本号]

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 版本号
VERSION="${1:-v1.0.0}"
VERSION="${VERSION#v}"
DIST_DIR="dist"
BUILD_DIR="build"

print_info "构建 AdGuardHome 私人定制安全版 ${VERSION}"

# 清理旧文件
print_info "清理旧的构建文件..."
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# 构建前端
print_info "构建前端..."
cd client
npm install --quiet --no-progress
npm run build-prod
cd ..

# 设置构建参数
CHANNEL="release"
VERSION_PKG="github.com/AdguardTeam/AdGuardHome/internal/version"
COMMIT_TIME=$(git log -1 --pretty=%ct 2>/dev/null || echo "0")
REVISION=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS="-s -w"
LDFLAGS="${LDFLAGS} -X ${VERSION_PKG}.version=v${VERSION}"
LDFLAGS="${LDFLAGS} -X ${VERSION_PKG}.channel=${CHANNEL}"
LDFLAGS="${LDFLAGS} -X ${VERSION_PKG}.committime=${COMMIT_TIME}"

# 定义构建目标
BUILD_TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm/6"
    "linux/arm/7"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

# 构建函数
build_binary() {
    local goos=$1
    local goarch=$2
    local goarm=$3
    local output_name="AdGuardHome"
    local output_dir="${goos}-${goarch}"
    
    if [ -n "$goarm" ]; then
        output_dir="${goos}-${goarch}-v${goarm}"
    fi
    
    if [ "$goos" = "windows" ]; then
        output_name="AdGuardHome.exe"
    fi
    
    print_info "构建 ${output_dir}..."
    
    mkdir -p "${DIST_DIR}/${output_dir}"
    
    env \
        CGO_ENABLED=0 \
        GOOS="${goos}" \
        GOARCH="${goarch}" \
        GOARM="${goarm:-}" \
        go build \
            --ldflags="${LDFLAGS}" \
            --trimpath \
            -o "${DIST_DIR}/${output_dir}/${output_name}" \
            .
    
    # 复制前端资源
    if [ -d "${BUILD_DIR}" ]; then
        cp -r "${BUILD_DIR}" "${DIST_DIR}/${output_dir}/"
    fi
    
    # 创建压缩包
    cd "${DIST_DIR}"
    if [ "$goos" = "windows" ]; then
        zip -r -q "AdGuardHome_linux_${goarch}.zip" "${output_dir}"
    else
        tar czf "AdGuardHome_${output_dir}.tar.gz" "${output_dir}"
    fi
    cd ..
    
    print_success "完成 ${output_dir}"
}

# 遍历构建目标
for target in "${BUILD_TARGETS[@]}"; do
    IFS='/' read -r goos goarch goarm <<< "$target"
    build_binary "$goos" "$goarch" "$goarm"
done

# 构建 agh 命令行工具
print_info "构建 agh 命令行工具..."
for target in "${BUILD_TARGETS[@]}"; do
    IFS='/' read -r goos goarch goarm <<< "$target"
    output_dir="${goos}-${goarch}"
    if [ -n "$goarm" ]; then
        output_dir="${goos}-${goarch}-v${goarm}"
    fi
    
    output_name="agh"
    if [ "$goos" = "windows" ]; then
        output_name="agh.exe"
    fi
    
    env \
        CGO_ENABLED=0 \
        GOOS="${goos}" \
        GOARCH="${goarch}" \
        GOARM="${goarm:-}" \
        go build \
            -o "${DIST_DIR}/${output_dir}/${output_name}" \
            ./cmd/agh/
done

print_success "构建完成!"

# 显示构建结果
echo ""
echo "=========================================="
echo "构建产物:"
echo "=========================================="
ls -la "${DIST_DIR}/"*.tar.gz 2>/dev/null || true
ls -la "${DIST_DIR}/"*.zip 2>/dev/null || true

# 计算校验和
print_info "计算 SHA256 校验和..."
cd "${DIST_DIR}"
sha256sum *.tar.gz *.zip 2>/dev/null > SHA256SUMS || \
    shasum -a 256 *.tar.gz *.zip 2>/dev/null > SHA256SUMS
cd ..

print_success "SHA256SUMS 已生成"
echo ""
echo "发布包位置: ${DIST_DIR}/"
echo "版本: v${VERSION}"
