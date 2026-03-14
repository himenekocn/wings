# 文件下载进度显示 API 文档

## 概述

此功能为 Wings daemon 添加了实时文件下载进度跟踪功能，支持通过 HTTP 轮询和 WebSocket 两种方式获取下载进度。

## API 端点

### 1. 获取下载进度 (HTTP)

**端点**: `GET /api/servers/{server_uuid}/files/download-progress`

**参数**:
- `download_id` (可选): 特定下载的 ID，不提供则返回所有下载进度

**响应示例**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "file_name": "server.jar",
  "progress": 0.75,
  "bytes": 78643200,
  "total": 104857600,
  "speed": 1048576,
  "status": "downloading",
  "timestamp": 1678800000
}
```

**状态字段**:
- `downloading`: 正在下载
- `completed`: 下载完成
- `failed`: 下载失败

### 2. 列出所有活动下载 (HTTP)

**端点**: `GET /api/servers/{server_uuid}/files/download-progress/list`

**响应示例**:
```json
{
  "downloads": [
    {
      "identifier": "550e8400-e29b-41d4-a716-446655440000",
      "file_name": "server.jar",
      "progress": 0.75,
      "status": "downloading"
    }
  ]
}
```

### 3. 取消下载 (HTTP)

**端点**: `DELETE /api/servers/{server_uuid}/files/download-progress/{download_id}`

**参数**:
- `download_id` (必需): 要取消的下载 ID（URL 路径参数）

**响应示例 (成功)**:
```json
{
  "message": "Download cancelled successfully",
  "download_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**响应示例 (下载不存在)**:
```json
{
  "error": "Download not found"
}
```

**响应示例 (权限错误)**:
```json
{
  "error": "Download does not belong to this server"
}
```

**HTTP 状态码**:
- `200 OK`: 取消成功
- `400 Bad Request`: 缺少下载 ID
- `403 Forbidden`: 下载不属于此服务器
- `404 Not Found`: 下载或服务器不存在

### 4. 实时进度更新 (WebSocket)

**端点**: `GET /api/servers/{server_uuid}/files/download-progress/ws`

**参数**:
- `token` (必需): JWT 认证令牌
- `download_id` (可选): 特定下载的 ID，不提供则订阅所有下载

**响应示例**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "file_name": "modpack.zip",
  "progress": 0.45,
  "bytes": 47185920,
  "total": 104857600,
  "speed": 2097152,
  "status": "downloading",
  "timestamp": 1678800005
}
```

## 使用示例

### 取消下载

```bash
# 取消特定下载
curl -X DELETE \
  'http://localhost:8080/api/servers/0b4aac59-b26b-42f8-96e8-55d4d157741a/files/download-progress/550e8400-e29b-41d4-a716-446655440000' \
  -H 'Authorization: Bearer YOUR_NODE_TOKEN'
```

### 查询下载进度

```bash
# 查询特定下载进度
curl 'http://localhost:8080/api/servers/0b4aac59-b26b-42f8-96e8-55d4d157741a/files/download-progress?download_id=550e8400-e29b-41d4-a716-446655440000' \
  -H 'Authorization: Bearer YOUR_NODE_TOKEN'

# 列出所有活动下载
curl 'http://localhost:8080/api/servers/0b4aac59-b26b-42f8-96e8-55d4d157741a/files/download-progress/list' \
  -H 'Authorization: Bearer YOUR_NODE_TOKEN'
```

**WebSocket 消息格式**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "file_name": "server.jar",
  "progress": 0.75,
  "bytes": 78643200,
  "total": 104857600,
  "speed": 1048576,
  "status": "downloading",
  "timestamp": 1678800000
}
```

**保持连接**:
- 客户端应每 30 秒发送一次 "ping" 消息
- 服务器会回复 "pong" 消息
- 服务器也会主动发送 Ping 帧保持连接

## 使用示例

### JavaScript (WebSocket)

```javascript
const token = 'your-jwt-token';
const downloadId = 'download-uuid';

const ws = new WebSocket(
  `ws://your-wings-server/download/progress/ws?token=${token}&download_id=${downloadId}`
);

ws.onopen = () => {
  console.log('Connected to progress stream');
  // 发送 ping 保持连接
  setInterval(() => {
    ws.send('ping');
  }, 30000);
};

ws.onmessage = (event) => {
  const progress = JSON.parse(event.data);
  console.log(`Download progress: ${(progress.progress * 100).toFixed(2)}%`);
  console.log(`Speed: ${formatSpeed(progress.speed)}`);
  
  if (progress.status === 'completed') {
    console.log('Download completed!');
    ws.close();
  } else if (progress.status === 'failed') {
    console.error('Download failed!');
    ws.close();
  }
};

function formatSpeed(bytesPerSec) {
  if (bytesPerSec >= 1024 * 1024 * 1024) {
    return (bytesPerSec / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
  } else if (bytesPerSec >= 1024 * 1024) {
    return (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
  } else if (bytesPerSec >= 1024) {
    return (bytesPerSec / 1024).toFixed(2) + ' KB/s';
  }
  return bytesPerSec + ' B/s';
}
```

### JavaScript (HTTP 轮询)

```javascript
const token = 'your-jwt-token';
const downloadId = 'download-uuid';

async function pollProgress() {
  const response = await fetch(
    `/download/progress?token=${token}&download_id=${downloadId}`
  );
  const progress = await response.json();
  
  console.log(`Download progress: ${(progress.progress * 100).toFixed(2)}%`);
  console.log(`Speed: ${formatSpeed(progress.speed)}`);
  
  if (progress.status === 'downloading') {
    // 继续轮询
    setTimeout(pollProgress, 1000);
  }
}

pollProgress();
```

### Go 语言示例

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
)

type ProgressEvent struct {
    ID        string  `json:"id"`
    FileName  string  `json:"file_name"`
    Progress  float64 `json:"progress"`
    Bytes     int64   `json:"bytes"`
    Total     int64   `json:"total"`
    Speed     int64   `json:"speed"`
    Status    string  `json:"status"`
    Timestamp int64   `json:"timestamp"`
}

func getProgress(token, downloadID string) (*ProgressEvent, error) {
    resp, err := http.Get(fmt.Sprintf(
        "http://wings-server/download/progress?token=%s&download_id=%s",
        token, downloadID,
    ))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var progress ProgressEvent
    if err := json.NewDecoder(resp.Body).Decode(&progress); err != nil {
        return nil, err
    }

    return &progress, nil
}
```

## 实现细节

### 进度跟踪

- 进度值范围：0.0 到 1.0
- 每 10% 记录一次日志
- 速度计算基于最近 1 秒的平均值
- 下载完成后进度信息保留 5 秒

### 安全特性

- 所有请求都需要有效的 JWT 令牌
- 令牌必须包含服务器 UUID
- 令牌只能使用一次（防止重放攻击）
- WebSocket 连接会验证服务器权限

### 性能优化

- 使用通道广播进度更新，避免锁竞争
- WebSocket 通道缓冲 100 条消息
- 自动清理过期的进度会话
- 支持同时跟踪多个下载

## 注意事项

1. **令牌有效期**: JWT 令牌通常有效期较短，确保在令牌过期前完成下载
2. **连接限制**: 每个下载可以支持多个 WebSocket 监听器
3. **资源清理**: 下载完成后 5 秒会自动清理进度信息
4. **错误处理**: 如果下载失败，进度事件的 `status` 字段会设置为 `failed`

## 故障排除

### 问题：WebSocket 连接立即关闭

**解决方案**:
- 检查 JWT 令牌是否有效
- 验证服务器 UUID 是否正确
- 检查 Wings 日志查看错误信息

### 问题：进度更新延迟

**解决方案**:
- 使用 WebSocket 而不是 HTTP 轮询获取实时更新
- 检查网络延迟
- 增加 HTTP 轮询间隔

### 问题：下载进度卡在某个值

**解决方案**:
- 检查网络连接
- 查看 Wings 日志是否有错误
- 验证磁盘空间是否充足
