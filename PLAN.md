# Androguard-Go 实施计划

## 总体进度

- [x] Phase 1: 代码审查 & 编译验证
- [ ] Phase 2: 核心工具模块 (util, androconf)
- [ ] Phase 3: APK 模块补全
- [ ] Phase 4: AXML 模块补全
- [ ] Phase 5: DEX 模块补全
- [ ] Phase 6: Analysis 模块补全
- [ ] Phase 7: Resources 模块补全
- [ ] Phase 8: Bytecode 模块 (PrettyShow, method2dot, JSON)
- [ ] Phase 9: Session 模块
- [ ] Phase 10: Misc 模块 (AnalyzeAPK, AnalyzeDex)
- [ ] Phase 11: CLI 扩展

## 详细任务分解

### Phase 2: 核心工具模块
- [ ] `core/config/config.go` - 配置管理 (androconf.py)
- [ ] `core/config/detect.go` - 文件类型检测 (is_android, is_android_raw)

### Phase 3: APK 模块补全
- [ ] 证书增强: GetCertificatesDER v1/v2/v3, GetPublicKeysDER
- [ ] 文件操作: GetFile, GetAllAttributeValues
- [ ] Manifest 增强: get_android_manifest_xml (lxml 等价物)
- [ ] 属性增强: get_res_value (资源引用解析)
- [ ] overlay/split 支持

### Phase 4: AXML 模块补全
- [ ] AXMLParser 迭器模式 (__next__, _do_next)
- [ ] AXMLPrinter is_packed 检测
- [ ] get_xml_obj 等价物 (DOM 构建)
- [ ] AXMLNode/AXMLElement 树结构

### Phase 5: DEX 模块补全
- [ ] 类型常量完善 (TypeItem, TypeList)
- [ ] MapItem, MapList 解析
- [ ] ODEX 支持 (OdexHeaderItem, OdexDependencies)
- [ ] EncodedField/EncodedMethod 增强
- [ ] ClassDefItem 增强
- [ ] get_regex_strings, get_source 等

### Phase 6: Analysis 模块补全
- [ ] create_xref 方法
- [ ] ExternalClass, ExternalMethod
- [ ] XRefNewInstance, XRefConstClass
- [ ] DEXBasicBlock 增强
- [ ] get_strings_analysis
- [ ] is_class_present

### Phase 7: Resources 模块补全
- [ ] get_packages_names, get_locales
- [ ] get_public_resources (XML 输出)
- [ ] get_string_resources, get_bool_resources 等
- [ ] get_resolved_res_configs
- [ ] get_res_id_by_key

### Phase 8: Bytecode 模块
- [ ] PrettyShow - 基本块彩色输出
- [ ] method2dot - DOT 格式 CFG
- [ ] method2json - JSON 格式 CFG
- [ ] vm2json - DEX JSON 导出
- [ ] FormatClassToJava, FormatDescriptorToPython 等

### Phase 9: Session 模块
- [ ] Session 结构体
- [ ] add, addAPK, addDEX 方法
- [ ] get_classes, get_strings, get_objects_apk 等

### Phase 10: Misc 模块
- [ ] AnalyzeAPK 便捷函数
- [ ] AnalyzeDex 便捷函数
- [ ] get_default_session

### Phase 11: CLI 扩展
- [ ] sign 命令 (签名信息)
- [ ] disasm 命令 (反汇编)
- [ ] decompile 命令 (反编译，如果 decompiler 完成)
- [ ] trace 命令 (如果 pentest 完成)
