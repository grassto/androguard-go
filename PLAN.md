# Androguard-Go 实施计划 & 进度

## ✅ 已完成

### Phase 1: 代码审查 & 编译验证
- Go 代码编译通过，所有测试通过
- 目录结构已匹配 Python androguard

### Phase 2: 核心工具模块
- [x] `core/config/config.go` - 配置管理 + 文件类型检测
- [x] `core/bytecode/bytecode.go` - PrettyShow, method2dot, JSON 导出

### Phase 3: Analysis 模块补全
- [x] `IsClassPresent(name)` - 检查类是否存在
- [x] `GetClassAnalysis(name)` - 获取类分析
- [x] `GetMethodAnalysisByName(name)` - 按方法名查找
- [x] `GetStringsAnalysis()` - 返回字符串分析 map
- [x] `CreateXref()` - 创建交叉引用
- [x] `GetPermissions()` - 提取权限字符串
- (已有) `GetExternalClasses/Methods`, `FindClasses/Methods/Strings/Fields`

### Phase 4: DEX 模块补全
- [x] `GetEncodedMethods()` - 获取所有编码方法
- [x] `GetEncodedMethodsClass(className)` - 获取类的所有方法
- [x] `GetEncodedFieldsClass(className)` - 获取类的所有字段
- [x] `GetEncodedMethodDescriptor(desc)` - 按描述符查找方法
- [x] `GetSuperclassName(classIdx)` - 获取超类名
- [x] `GetClassAnnotations(classIdx)` - 获取类注解

### Phase 5: Resources 模块补全
- [x] `GetPackagesNames()` - 获取所有包名
- [x] `GetLocales(packageName)` - 获取所有 locale
- [x] `GetTypes(packageName, locale)` - 获取资源类型
- [x] `GetStringResources(packageName)` - 获取字符串资源
- [x] `GetIntegerResources(packageName)` - 获取整数资源
- [x] `GetBoolResources(packageName)` - 获取布尔资源
- [x] `GetColorResources(packageName)` - 获取颜色资源
- [x] `GetDimenResources(packageName)` - 获取尺寸资源
- [x] `GetIDResources(packageName)` - 获取 ID 资源
- [x] `GetResIDByKey(package, type, key)` - 按键获取资源 ID
- [x] `GetPublicResources(packageName)` - 获取公共资源列表
- [x] `GetResourceXMLName(resID)` - 资源 ID 转 XML 名称
- [x] `GetResolvedStrings()` - 获取解析后的字符串
- [x] `GetTypeConfigs()` - 获取类型配置变体
- [x] `GetResConfigs()` - 获取资源配置条目
- [x] `GetItems()` - 获取所有资源条目
- [x] `GetResolvedResConfigs()` - 获取解析后的资源配置

## ⏳ 待完成 (按优先级)

### Priority 1 - APK 模块 (影响基本使用)
- [ ] `GetAndroidManifestXML()` - 返回 XML Element 树
- [ ] `GetAppIcon()` - DPI 解析后的图标路径
- [ ] `GetAppName(locale)` - locale 感知的应用名
- [ ] `GetCertificateDER()` - 获取 DER 格式证书
- [ ] `GetCertificatesDERV2/V3()` - v2/v3 签名证书
- [ ] `GetPublicKeysDERV2/V3()` - v2/v3 公钥
- [ ] `GetSignatureNames()` - 签名文件名列表
- [ ] `IsSignedV31()` - v3.1 签名检测
- [ ] `GetAllAttributeValue()` - 跨标签属性查询

### Priority 2 - AXML/ARSC 增强
- [ ] `AXMLParser` 迭代器模式 (Next 方法)
- [ ] `AXMLPrinter.IsPacked()` - 检测打包/混淆
- [ ] `AXMLPrinter.GetXML()` - DOM 树构建

### Priority 3 - DEX 增强
- [ ] ODEX 支持 (OdexHeaderItem, OdexDependencies)
- [ ] MapItem/MapList 解析
- [ ] `EncodedMethod.GetSource()` - 反编译源码 (需要 decompiler)

### Priority 4 - CLI 扩展
- [ ] `sign` 命令 - 签名信息
- [ ] `disasm` 命令 - 反汇编
- [ ] `dump` 命令 - DEX 转储

### Priority 5 - 非核心模块 (可选)
- [ ] `session` - 会话管理
- [ ] `misc` - 便捷函数 (AnalyzeAPK, AnalyzeDex)
- [ ] `util` - 工具函数
- [ ] `decompiler` - 反编译器
