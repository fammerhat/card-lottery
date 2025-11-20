# 即梦4.0 API 配置指南

## ⚠️ 重要说明

**你提供的AK/SK是即梦3.0的配置，已配置完成。**

**即梦4.0需要不同的配置：**
- 需要在控制台创建推理接入点
- 获取Bearer Token（不是AK/SK）
- 获取API调用地址

## 第一步：在火山引擎控制台获取即梦4.0配置信息

### 1. 登录火山引擎控制台
- 访问：https://console.volcengine.com/
- 登录你的账号

### 2. 开通即梦4.0服务
- 在控制台找到"即梦AI-图片生成4.0"服务
- 点击"免费开通"或"立即使用"

### 3. 创建推理接入点
- 进入即梦4.0服务页面
- 找到"推理接入点"或"API接入"选项
- 点击"创建推理接入点"
- 选择绑定 **Seedream-4.0** 模型
- 创建完成后，你会看到：
  - **API调用地址**（类似：`https://xxx.volcengineapi.com/v1/images/generations`）
  - **API密钥**（Bearer Token，一串长字符串）

### 4. 复制配置信息
- 复制 **API调用地址** → 这就是 `JIMENG_V4_API_URL`
- 复制 **API密钥** → 这就是 `JIMENG_V4_API_TOKEN`

## 第二步：在 Render 配置环境变量

### 方法1：通过 Render Dashboard 配置（推荐）

1. 登录 Render Dashboard：https://dashboard.render.com/
2. 选择你的 Web Service
3. 点击左侧菜单的 **Environment**
4. 点击 **Add Environment Variable** 按钮
5. 添加以下三个环境变量：

   **变量1：**
   - Key: `JIMENG_V4_API_URL`
   - Value: 你从控制台复制的API调用地址
   - 示例：`https://xxx.volcengineapi.com/v1/images/generations`

   **变量2：**
   - Key: `JIMENG_V4_API_TOKEN`
   - Value: 你从控制台复制的API密钥（Bearer Token）
   - 示例：`sk-xxxxxxxxxxxxxxxxxxxxx`

   **变量3：**
   - Key: `USE_JIMENG_V4`
   - Value: `true`

6. 点击 **Save Changes**
7. 重新部署服务（Render会自动重新部署）

### 方法2：通过代码配置（本地测试）

在项目根目录创建 `.env` 文件（不要提交到Git）：

```bash
JIMENG_V4_API_URL=https://你的API地址
JIMENG_V4_API_TOKEN=你的Bearer Token
USE_JIMENG_V4=true
```

## 第三步：验证配置

配置完成后，重新部署服务，然后测试图片生成功能。如果配置正确，应该可以正常生成图片了。

## 常见问题

### Q: 找不到"推理接入点"在哪里？
A: 可能在"API管理"、"服务配置"或"接入管理"等菜单下，不同版本的控制台位置可能不同。

### Q: API密钥格式是什么样的？
A: 通常是一串以 `sk-` 开头的字符串，或者是一串随机字符。

### Q: 如何确认API地址是否正确？
A: API地址通常包含 `volcengineapi.com` 或类似的域名，并且路径包含 `/v1/images/generations` 或类似路径。

### Q: 配置后还是报错怎么办？
A: 
1. 检查环境变量是否正确设置
2. 检查API密钥是否有效（没有过期）
3. 检查API地址是否正确
4. 查看日志中的错误信息

## 示例配置

假设你从控制台获取到：
- API地址：`https://api.volcengine.com/v1/images/generations`
- API密钥：`sk-abc123def456ghi789`

那么在 Render 中应该配置：
```
JIMENG_V4_API_URL=https://api.volcengine.com/v1/images/generations
JIMENG_V4_API_TOKEN=sk-abc123def456ghi789
USE_JIMENG_V4=true
```

