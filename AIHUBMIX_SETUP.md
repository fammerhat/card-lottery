# Aihubmix API 配置指南

## 什么是 Aihubmix？

Aihubmix 是一个统一的 AI API 网关，支持多种图片生成模型，包括即梦4.0。**最大的优势是使用简单的 Bearer Token 认证，无需复杂的签名算法！**

## 第一步：获取 Aihubmix API Token

1. **访问 Aihubmix 官网**：https://aihubmix.com
2. **注册账号**（如果还没有）
3. **在控制台获取 API Token**
   - 登录后进入控制台
   - 找到 API Keys 或 Token 管理
   - 创建或复制你的 API Token（格式类似：`sk-xxxxxxxxxxxxx`）

## 第二步：在 Render 配置环境变量

### 方法：通过 Render Dashboard 配置

1. 登录 Render Dashboard：https://dashboard.render.com/
2. 选择你的 Web Service
3. 点击左侧菜单的 **Environment**
4. 点击 **Add Environment Variable** 按钮
5. 添加以下两个环境变量：

   **变量1：**
   - Key: `AIHUBMIX_API_TOKEN`
   - Value: 你从 Aihubmix 控制台复制的 API Token
   - 示例：`sk-abc123def456ghi789`

   **变量2：**
   - Key: `USE_AIHUBMIX`
   - Value: `true`

6. 点击 **Save Changes**
7. 重新部署服务（Render会自动重新部署）

## 优势

✅ **无需复杂签名**：只需要一个 Bearer Token  
✅ **接口统一**：所有模型使用相同的调用方式  
✅ **支持多种模型**：包括即梦4.0、Flux、Qwen等  
✅ **简单易用**：比直接调用火山引擎简单得多  

## 注意事项

⚠️ **图生图支持**：根据文档，Aihubmix 的即梦4.0接口可能主要支持文生图。如果图生图不工作，可能需要：
1. 联系 Aihubmix 技术支持确认图生图参数
2. 或使用其他支持图生图的模型（如 Qwen-Image-Edit）

## 测试

配置完成后，重新部署服务，然后测试图片生成功能。如果配置正确，应该可以正常生成图片了。

## 常见问题

### Q: Aihubmix 是免费的吗？
A: 需要查看 Aihubmix 的定价页面，通常有免费额度。

### Q: 如何确认 API Token 是否正确？
A: API Token 通常是一串以 `sk-` 开头的字符串。

### Q: 如果图生图不工作怎么办？
A: 可以尝试：
1. 检查 API 返回的错误信息
2. 联系 Aihubmix 技术支持
3. 或使用其他支持图生图的模型

