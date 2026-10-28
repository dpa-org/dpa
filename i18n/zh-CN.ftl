# dpa i18n resource: Simplified Chinese (zh-CN).
# Syntax: one "key = value" per line; only \\ and \n are decoded escapes.
# Sections: err / msg / cli / op_descs / arg_descs / legacy.

# --- err ---
err.aes_decrypt = AES 解密失败（密钥/IV/密文不匹配或已损坏）: {}
err.aes_init = AES 初始化失败: {}
err.aes_key_len = AES 密钥长度须为 16/24/32 字节，当前 {}
err.analyze_hash_empty = 哈希识别输入为空；请提供十六进制摘要
err.arg_type = 参数 '{}' 仅支持字符串/数字/布尔
err.bad_byteswap_width = 字节交换宽度须为 2/4/8，当前 {}
err.bad_chacha_key_len = ChaCha20 密钥长度须为 32 字节，当前 {}
err.bad_escape = 非法的百分号转义，位于 '{}' 附近
err.bad_level = 压缩级别须为 0-9，当前 {}
err.bad_quality = Brotli 质量须为 0-11，当前 {}
err.bad_lang = 未知语言 '{}'（支持 en / zh-CN），已回退为英文
err.bad_nonce_len = ChaCha20 nonce 长度须为 12 字节，当前 {}
err.bad_padding = 未知填充方式: {}（仅支持 pkcs7 / none）
err.bad_timestamp = 参数 'timestamp' 必须是非负整数（got '{}'）
err.bad_os = 参数 'os' 必须是 0-255 的整数（got '{}'）
err.base32_decode = Base32 解码失败: {}
err.base32_alphabet_len = Base32 字母表必须为 32 或 33 个字符（当前 {} 个）
err.base32_dup_char = Base32 字母表包含重复字符
err.base32_invalid = Base32 解码失败: 非法字符
err.base32_padding = Base32 解码失败: 非法填充
err.base32_tail = Base32 解码失败: 非法尾部长度（长度模 8 余 1/3/6）
err.base32_strict_tail = Base32 解码失败: 尾部存在非零位
err.base58_alphabet_len = Base58 字母表必须为 58 个字符（当前 {} 个）
err.base58_dup_char = Base58 字母表包含重复字符
err.base58_invalid_at = Base58 解码失败: 字符 '{}'（位置 {}）不在字母表中
err.base64_decode = Base64 解码失败: {}
err.base64_empty_group = Base64 解码失败: 空组
err.base64_invalid = Base64 解码失败: 非法字符
err.base64_padding = Base64 解码失败: 非法填充
err.base64_tail = Base64 解码失败: 尾部单字符无法解码
err.base64_strict_len = Base64 解码失败: 长度为 4n+1（严格模式下非法）
err.base64_strict_pad_pos = Base64 解码失败: 填充字符不在末尾
err.base64_strict_pad_len = Base64 解码失败: 填充输入长度不是 4 的倍数
err.base64url_decode = Base64 URL 解码失败: {}
err.base64_alphabet_len = Base64 字母表必须为 64 或 65 个字符（当前 {} 个）
err.base64_bad_range = Base64 字母表: 无效的范围表达式（如降序 A-1）
err.base64_dup_char = Base64 字母表包含重复字符
err.binary_invalid = 二进制解码失败: 非法字符（应为 0/1）
err.binary_odd = 二进制解码失败: 长度不是 8 的倍数
err.block_alignment = padding=none 时输入长度必须是块大小的整数倍（当前为 {}）
err.blowfish_key_len = Blowfish 密钥长度须在 4..=56 字节，当前 {}
err.bool_invalid = 参数必须为 true/false（当前 '{}'）
err.int_invalid = 参数必须为非负整数（当前 '{}'）
err.bytes_not_num = 参数 bytes 不是合法数字: {}
err.bytes_range = 参数 bytes 须在 1..=1000000 之间，当前 {}
err.bzip2_compress = Bzip2 压缩失败: {}
err.bzip2_decompress = Bzip2 解压失败: {}
err.charcode_invalid = 码点解码失败: 非法码点 '{}'
err.cipher_init = 密码算法初始化失败: {}
err.ciphertext_len = 密文长度须为块大小的倍数，当前 {}
err.compress_failed = 压缩失败: {}
err.compressor_stuck = 压缩器未消费输入且未结束（状态: {}）
err.create_outdir_failed = 创建输出目录失败: {}
err.create_outfile_failed = 创建输出文件失败: {}
err.datetime_parse_failed = 无法解析日期时间 '{}'（支持 RFC3339 / RFC2822 / 常见格式 / Unix 秒）
err.datetime_delta_two_lines = DateTime Delta 需要恰好两行输入
err.datetime_delta_bad = 无效的增量表达式 '{}'
err.decimal_invalid = 十进制解码失败: 非法数值 '{}'
err.decimal_range = 十进制解码失败: '{}' 超出范围（0-255）
err.decompressor_stuck = 解压器未消费输入且未产出（状态: {}）
err.des3_key_len = 3DES 密钥长度须为 24 字节，当前 {}
err.des_decrypt = DES 解密失败（密钥/IV/密文不匹配或已损坏）: {}
err.des_init = DES 初始化失败: {}
err.des_key_len = DES 密钥长度须为 8 字节，当前 {}
err.empty_from = 参数 from 不能为空
err.empty_iv = 参数 iv 不能为空
err.empty_key = 参数 key 不能为空
err.empty_steps = 流程没有步骤（steps 为空）
err.empty_sub = 参数 sub 不能为空
err.flush_out_failed = 刷新输出失败: {}
err.flush_outfile_failed = 刷新输出文件失败: {}
err.gcm_auth_failed = GCM 认证失败（标签不匹配）
err.gcm_not_streamable = GCM 模式不支持流式处理
err.gcm_tag_len = GCM 校验标签必须为 16 字节（当前为 {}）
err.gcm_tag_mismatch = GCM 认证失败（标签不匹配）
err.gzip_bad_header = gzip 解压失败: 无效的 gzip 头
err.gzip_compress = gzip 压缩失败: {}
err.gzip_crc = gzip 解压失败: CRC32 校验失败
err.gzip_decompress = gzip 解压失败: {}
err.gzip_incomplete = gzip 解压失败: 数据不完整（未收到完整 gzip 流）
err.gzip_incomplete_trailer = gzip 解压失败: 数据不完整（缺少尾部）
err.gzip_filename_nul = gzip 文件名不能包含 NUL 字节
err.gzip_len = gzip 解压失败: 长度校验失败
err.hex_decode = Hex 解码失败: {}
err.hex_invalid = Hex 解码失败: 非法字符
err.hex_ignore_invalid = ignore_non_alphabet 取值无效: {}
err.hex_odd = Hex 解码失败: 字符数为奇数
err.hmac_sha1_init = HMAC-SHA1 初始化失败: {}
err.hmac_sha256_init = HMAC-SHA256 初始化失败: {}
err.hmac_sha512_init = HMAC-SHA512 初始化失败: {}
err.init_stream_failed = 第 {} 步（{}）初始化失败: {}
err.invalid_length = 无效长度: {}
err.invalid_number = 无效数字: {}
err.iv_len = IV 长度须与块大小一致，当前 {}
err.json_parse = JSON 解析失败: {}
err.key_not_hex = 密钥不是合法十六进制: {}
err.lzma.format = LZMA 格式必须为 xz 或 lzma（当前 '{}'）
err.lzma_compress = LZMA 压缩失败: {}
err.lzma_decompress = LZMA 解压失败: {}
err.min_not_num = 参数 min 不是合法数字: {}
err.min_range = 参数 min 须在 1..=100000 之间，当前 {}
err.missing_from = 缺少参数 from
err.missing_gcm_tag = 缺少参数: tag
err.missing_format = 缺少必填参数 format
err.missing_key = 缺少参数 key
err.missing_n = 缺少参数 n
err.missing_nonce = 缺少参数 nonce
err.missing_path = 缺少参数 path
err.missing_pattern = 缺少参数 pattern

err.bad_builtin_regex = 未知的内置正则模板: {}
err.missing_replacement = 缺少参数 replacement
err.missing_sub = 缺少参数 sub
err.missing_tag = 缺少参数: tag
err.missing_to = 缺少参数 to
err.n_inputs_failed = {} 个输入处理失败:\n{}
err.batch_partial_failure = {} 个输入中的 {} 个处理失败；首个错误：{}
err.fork_depth = Fork 嵌套超过最大深度 {}
err.n_not_num = 参数 n 不是有效数字: {}
err.recipe_json_parse = recipe JSON 解析失败
err.recipe_json_top_array = recipe JSON 顶层必须是数组
err.recipe_element_object = recipe 元素必须是对象
err.recipe_missing_op = recipe 元素缺少 op 字段
err.recipe_args_array = args 必须是数组
err.recipe_missing_paren = recipe 语法错误：操作名后缺少 '('（位置 {}）
err.recipe_unclosed_paren = recipe 语法错误：操作 {} 的参数括号未闭合
err.recipe_unfinished_escape = recipe 语法错误：字符串转义不完整
err.recipe_arg_utf8 = recipe 字符串参数不是合法 UTF-8
err.recipe_param_utf8 = recipe 参数不是合法 UTF-8
err.url_missing_recipe = URL 中缺少 recipe 参数
err.url_recipe_decode = recipe 参数 URL 解码失败
err.url_input_decode = input 参数 URL 解码失败
err.url_input_base64 = input 参数不是合法 Base64
err.url_percent_incomplete = URL 百分号编码不完整（位置 {}）
err.url_percent_invalid = URL 百分号编码非法：%{}
err.url_decode_utf8 = URL 解码结果不是合法 UTF-8
err.not_filetime = 无效的 FILETIME 值: {}
err.filetime_bad_unit = 未知 FILETIME 单位（可选：ticks / us / ms / s）
err.not_unix_time = 无效的 UNIX 时间戳: {}
err.not_utf8_match = 输入不是合法 UTF-8，正则匹配仅支持文本
err.not_utf8_replace = 输入不是合法 UTF-8，正则替换仅支持文本
err.octal_invalid = 八进制解码失败: 非法字符（应为 0-7）
err.octal_odd = 八进制解码失败: 长度不是 3 的倍数
err.op_not_found = 未找到操作 '{}'（可用 dpa list 查看全部操作）
err.invalid_category = 未知分类 '{}'（可用：{}）；可用 dpa list -c <category> 查看
err.out_rel_conflict = 输出相对路径 '{}' 冲突：'{}' 与 '{}'；请使用不同文件名或分开的输出目录
err.parse_flow_failed = 流程文件解析失败: {}
hint.flow_shape = 流程为 YAML 文档，形如 `ops: [{op: <名称>, args: {...}}]`（详见 README）
err.path_index = 路径索引非法: [{}]
err.path_not_found_idx = 路径不存在: [{}]
err.path_not_found_key = 路径不存在: {}
err.pkg_format = 不是 dpa 流程包（格式 '{}'，应为 '{}'）
err.pkg_parse = 包 YAML 解析失败: {}
err.pkg_serialize = 包序列化失败: {}
err.pkg_unknown_op = 第 {} 步：包内未知操作 '{}'
err.pkg_version = 不支持的包版本 {}（应为 {}）
err.plugin_abi_version = 插件 ABI 版本不匹配：宿主 v{}，插件 v{}
err.plugin_args_json = 插件参数 JSON 无效: {}
err.plugin_args_json_obj = 插件参数 JSON 必须是对象
err.plugin_load_failed = 插件加载失败 {}: {}
err.plugin_no_ops = 插件未导出任何操作
err.plugin_partial_stream = 插件导出了不完整的流式 ABI（init/write/finish/free 必须同时提供）
err.plugin_run_failed = 插件操作执行失败
err.plugin_stream_failed = 插件流式操作失败
err.plugin_stream_init_failed = 插件流式操作初始化失败
err.proto_bad_ipv4 = 非 IPv4 数据包（版本={}）
err.proto_bad_ipv6 = 非 IPv6 数据包（版本={}）
err.proto_bad_tcp = 无效的 TCP 头
err.proto_bad_tls = 无效的 TLS 记录
err.proto_bad_hex = 输入不是合法的十六进制字符串
err.proto_truncated = 输入过短，无法解析 {} 头（需要 {} 字节，实际 {} 字节）
err.rc4_key_len = RC4 密钥长度须在 1..=256 字节，当前 {}
err.read_flow_failed = 读取流程文件 '{}' 失败: {}
err.read_input_failed = 读取输入文件 '{}' 失败: {}
err.read_pkg_failed = 读取包文件失败: {}
err.regex_compile = 正则编译失败: {}
err.sm4_decrypt = SM4 解密失败（密钥/IV/密文不匹配或已损坏）: {}
err.sm4_init = SM4 初始化失败: {}
err.sm4_key_len = SM4 密钥长度须为 16 字节，当前 {}
err.ssdeep.compare.needs_two = ssdeep 比较需要恰好两个由 '{}' 分隔的签名
err.stdin_no_dir_out = stdin 输入不支持 -o 目录模式
err.step_failed = 第 {} 步（{}）执行失败: {}
err.stream_failed = 流式处理失败: {}
err.stream_finished = 流已结束，不能再写入
err.stream_read_failed = 流式读取输入失败: {}
err.system_time = 系统时间异常: {}
err.tea_key_len = TEA 系列密钥长度须为 16 字节，当前 {}
err.tea_block_misaligned = TEA 输入长度未对齐 8 字节块；请用 padding=pkcs7 或 none
err.tea_bad_padding = TEA 填充校验失败（可能密钥或模式不匹配）
err.thread_pool = 创建线程池失败: {}
err.top_not_num = 参数 top 不是合法数字: {}
err.uuid_bad_namespace = 无效的命名空间 UUID '{}'
err.uuid_need_namespace = UUID v3/v5 需要 namespace 参数
err.uuid_need_name = UUID v3/v5 需要 name 参数
err.top_range = 参数 top 须在 1..=256 之间，当前 {}
err.unknown_algo = 未知摘要算法: {}（支持 sha1 / sha256 / sha512）
err.unknown_crc = 未知 CRC-{} 变体: {}（支持 {}）
err.bad_rounds = 无效的 rounds 值: {}
err.unknown_hash_variant = 未知哈希变体: {}（支持 {}）
err.unknown_mode = 未知模式: {}（支持 {}）
err.xor.key_length = 参数 'key_length' 必须为 1 或 2（当前 {}）
err.xor.scheme = 未知方案: {}（支持 {}）
err.xor.bruteforce_scheme = XOR 暴力破解仅支持 standard/input-differential/output-differential 方案
err.unknown_op = 第 {} 步：未知操作 '{}'（可用 dpa list 查看全部操作）
err.type_mismatch = 第 {} 步：类型不匹配 - 上游产出 {}，但 {} 期望输入 {}。请先插入显式转换步骤（如 hex:encode / hex:decode / base64:encode / base64:decode）
err.unknown_output_format = 未知输出格式 '{}'，可选 raw | hex
err.unknown_unit = 未知单位: {}（支持: s / ms / us / ns）
err.unpad = PKCS#7 去填充失败: {}
err.utf8_invalid = 码点编码失败: 输入不是合法 UTF-8
err.walk_dir_failed = 遍历目录失败: {}
err.write_outfile_failed = 写入输出文件失败: {}
err.write_stdout = 写入 stdout 失败: {}
err.zlib_compress = zlib 压缩失败: {}
err.zlib_decompress = zlib 解压失败: {}
err.zlib_incomplete = zlib 解压失败: 数据不完整
err.base62_alphabet_len = Base62 字母表必须为 62 个字符（当前 {} 个）
err.base62_dup_char = Base62 字母表包含重复字符
err.base62_invalid_at = Base62 解码失败: 字符 '{}'（位置 {}）不在字母表中
err.base85_alphabet_len = Base85 字母表必须为 85 个字符（当前 {} 个）
err.base85_dup_char = Base85 字母表包含重复字符
err.base85_invalid_at = Base85 解码失败: 字符 '{}'（位置 {}）不在字母表中
err.base85_z_mid_group = Ascii85 组内不允许出现 'z'
err.base85_incomplete = Ascii85 组不完整
err.punycode_utf8 = Punycode 编码失败：输入不是合法 UTF-8
err.qp_wrap_invalid = Quoted-printable 行宽必须是非负整数: '{}'
err.punycode_prefix_missing = Punycode 解码需要 xn-- 前缀，但输入为 '{}'
err.hex_delimiter_invalid = 未知的 hex 分隔符 '{}'（可选 none/space/comma/semicolon/colon/newline/crlf）
err.punycode_invalid = 无效的 Punycode 输入: {}
err.punycode_invalid_basic = 无效的 Punycode 输入：基本码点不是 ASCII
err.punycode_overflow = Punycode 输入过大

# --- msg ---
msg.args_header = 参数:
msg.col_category = 分类
msg.col_desc = 说明
msg.col_family = 家族
msg.col_kind = 动作
msg.col_op = 操作名
msg.flow_author = 作者: {}
msg.flow_desc = [dpa] 流程说明: {}
msg.flow_exported = 已导出流程包到 {}
msg.flow_homepage = 主页: {}
msg.flow_id = ID: {}
msg.flow_imported = 已导入流程 {} 到 {}
msg.flow_license = 许可: {}
msg.flow_meta = [dpa] 流程: {} — {}
msg.flow_name = [dpa] 流程: {}
msg.flow_steps = 步骤: {}
msg.flow_tags = 标签: {}
msg.flow_tags_none = 标签: 无
msg.flow_version = 版本: {}
msg.no_args = 参数: 无
msg.no_match = （无匹配操作）
msg.op_suggest = 您要找的是：{}？
msg.op_category = 分类: {}
msg.op_count = \n共 {} 个操作。
msg.op_description = 说明: {}
msg.op_family = 家族: {}
msg.op_kind = 动作: {}
msg.op_name = 操作: {}
msg.opt = 可选
msg.plugins_loaded = 已加载 {} 个操作（插件目录 {}）
msg.default_plugins_loaded = 已加载 {} 个操作（默认插件目录）
msg.discover_plugins_warning = 正在扫描默认插件目录：{}——其中的原生代码将以你的权限执行
msg.plugin_op_skipped = 插件操作 '{}' 与已有操作冲突，已跳过
msg.req = 必填
msg.step_missing = 缺失
msg.step_ok = 可用
# --- cli ---
cli.about_long = dpa：数据处理与分析。\n在命令行上运行多步的数据变换与分析流程。\n流程是一份 YAML 文件，可审阅、可纳入版本管理、可反复运行。
cli.about_short = dpa — 数据处理与分析
cli.category_help_prefix = 按分类过滤
cli.flow_about = 流程管理：manifest / export / import
cli.flow_export_about = 导出流程为可分享的 .dpaflow 包
cli.flow_import_about = 导入 .dpaflow 包并校验其操作
cli.flow_manifest_about = 查看流程清单与操作依赖
cli.input_help = 输入文件/目录；'-' 或省略时从标准输入读取。目录会被展开为其中全部文件（见 --recursive）
cli.jobs_help = 并行处理文件数；0 表示按 CPU 核数自动
cli.lang_help = 人话文本语言：en | zh-CN（默认 en）
cli.version_help = 打印版本后退出
cli.list_about = 列出可用操作
cli.list_group_help = 按 family | kind | category 分组展示
cli.list_search_help = 按关键词过滤操作（名称 / 分类 / 家族 / 动作 / 说明）
msg.group_header = == {} ==
cli.op_about = 查看单个操作详情
cli.op_name_help = 操作标识，如 dpa:base64:decode
cli.op_run_about = 直接对输入运行单个操作，无需流程文件
cli.op_run_name_help = 操作标识，如 dpa:base64:decode（用 `dpa list` 查看全部）
cli.op_run_args_help = 该操作的参数与输入；`dpa op <名字> --help` 可列出该操作的参数
err.unknown_op_name = 未知操作 '{}'（可用 `dpa list` 查看全部操作）
err.op_missing_name = 缺少操作名（可用 `dpa list` 查看全部操作）
err.op_arg_reserved = 操作 '{}' 声明的参数 '{}' 与 `dpa op` 命令保留的选项同名
err.clap.missing_value = 缺少参数值：{}
err.clap.invalid_value = 参数值无效：{}
err.clap.unknown_argument = 未知参数：{}
err.clap.invalid_subcommand = 未知子命令：{}
cli.output_format_help = 输出格式：raw | hex（默认 raw，可被流程文件内 output 字段覆盖）
cli.hex_help = --output-format hex 的快捷写法
cli.common_options_heading = 通用选项
cli.output_help = 输出文件（单输入时）或输出目录（多输入/目录输入时），自动创建
cli.pkg_help = 包文件（.dpaflow）
cli.plugins_help = 存放 dpa 插件动态库（.dll/.so/.dylib）的目录，启动时加载
cli.discover_plugins_help = 主动扫描默认插件目录（不安全：会加载其中找到的原生代码）
cli.recipe_about = CyberChef recipe 转换：URL / CHEF / JSON 三格式互转
cli.recipe_convert_about = 转换 CyberChef recipe（URL / CHEF / JSON 互转，支持中英操作名翻译）
cli.recipe_from_default = auto
cli.recipe_from_help = 输入格式：url | chef | json（默认自动识别）
cli.recipe_input_help = 待转换的 recipe 文本（或 URL）
cli.recipe_lang_help = 操作名翻译为 zh | en（默认保持原样）
cli.recipe_to_help = 输出格式：url | chef | json（必填）
cli.recursive_help = 递归展开输入目录（默认只处理目录直接子文件）
cli.run_about = 运行一个流程
cli.run_flow_help = 流程文件路径（YAML）。配合 -e 时，此位置改为第一个输入
cli.run_eval_help = 以内联 YAML 作为流程，替代流程文件

# --- op_descs (structured keys) ---
op.adler32.desc = Adler-32 校验和（RFC 1950；大端 4 字节；hex 请用 dpa:hex:encode）


op.aes.decrypt.desc = AES 解密（模式：ecb/cbc/cfb/ofb/ctr/gcm；块模式用 PKCS#7）
op.aes.encrypt.desc = AES 加密（模式：ecb/cbc/cfb/ofb/ctr/gcm；块模式用 PKCS#7）
op.analyze.file.type.desc = 通过魔数识别文件类型
op.analyze.hash.desc = 从摘要识别可能的哈希算法
op.asn1.parse.desc = 解析 DER 编码的 ASN.1 结构（原始 DER 字节或十六进制），输出标签、长度与值的 JSON 树
op.base32.decode.desc = Base32 解码（自定义字母表，可忽略非字母表字符，可选严格模式）
op.base32.encode.desc = Base32 编码（字母表预设或 32/33 字符，支持范围展开，可带填充）
op.base58.decode.desc = Base58 解码（自定义字母表，可忽略非字母表字符）
op.base58.encode.desc = Base58 编码（字母表预设 bitcoin/ripple 或 58 字符，支持范围展开）
op.base62.decode.desc = Base62 解码（自定义字母表，可忽略非字母表字符）
op.base62.encode.desc = Base62 编码（字母表预设 standard 或 62 字符，支持范围展开）
op.base64.decode.desc = Base64 解码（自定义字母表，可忽略非字母表字符，可选严格模式）
op.base64.encode.desc = Base64 编码（自定义字母表：预设或 64/65 字符，支持范围展开）
op.base64.url.decode.desc = Base64 URL 安全解码（可自定义字母表，可选忽略非字母表字符，可选严格模式）
op.base64.url.encode.desc = Base64 URL 安全编码（- 与 _，可带填充）
op.base85.decode.desc = Ascii85 解码（Adobe 字母表，支持 z 压缩与空白）
op.base85.encode.desc = Ascii85 编码（Adobe 字母表，全零组可选 z 压缩）
op.binary.decode.desc = 二进制转字节（每字节 8 位，容忍空白与分隔符）
op.binary.encode.desc = 字节转二进制（每字节 8 位，可配置分隔符）
op.bitwise.and.desc = 按位与：每个字节与密钥字节循环相与
op.bitwise.or.desc = 按位或：每个字节与密钥字节循环相或
op.bitwise.rotate-left.desc = 按位循环左移：每个字节循环左移 N 位（1-7）
op.bitwise.rotate-right.desc = 按位循环右移：每个字节循环右移 N 位（1-7）
op.bitwise.shift-left.desc = 按位左移：每个字节左移 N 位（1-7，低位补零）
op.bitwise.shift-right.desc = 按位右移：每个字节右移 N 位（1-7，高位补零）
op.bitwise.xor.arg.key = 密钥字节（对输入循环使用）
op.bitwise.xor.desc = 按位异或：每个字节与密钥字节循环异或
op.blake2b.256.desc = BLAKE2b 摘要，256 位输出（原始字节；hex 请用 dpa:hex:encode）


op.blake2b.512.desc = BLAKE2b-512 摘要（原始字节；hex 请用 dpa:hex:encode）


op.blake2b.384.desc = BLAKE2b-384 摘要（原始字节；hex 请用 dpa:hex:encode）


op.blake2s.256.desc = BLAKE2s-256 摘要（原始字节；hex 请用 dpa:hex:encode）


op.count.arg.mode = 统计模式：substring（默认）或 lines（类似 wc -l）
op.hotp.arg.algo = HMAC 算法：sha1（默认）/ sha256 / sha512
op.md4.desc = MD4 摘要（原始字节；hex 请用 dpa:hex:encode）


op.sha3.224.desc = SHA3-224 摘要（原始字节；hex 请用 dpa:hex:encode）
op.sha3.384.desc = SHA3-384 摘要（原始字节；hex 请用 dpa:hex:encode）
op.timestamp.to.date.arg.unit = 输入单位：s（默认）/ ms / us / ns
op.totp.arg.algo = HMAC 算法：sha1（默认）/ sha256 / sha512
op.xxhash32.arg.seed = XXHash32 种子值（默认 0）
op.xxhash32.desc = XXHash32 校验和（原始 4 字节，seed 0；hex 请用 dpa:hex:encode）


op.xxhash64.arg.seed = XXHash64 种子值（默认 0）
op.xxhash64.desc = XXHash64 校验和（原始 8 字节，seed 0；hex 请用 dpa:hex:encode）


op.blowfish.decrypt.desc = Blowfish 解密（模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
op.blowfish.encrypt.desc = Blowfish 加密（模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
op.brotli.compress.desc = Brotli 压缩（RFC 7932）
op.brotli.decompress.desc = Brotli 解压（RFC 7932）
op.bzip2.compress.desc = Bzip2 压缩（libbz2，级别 1-9）
op.bzip2.compress.arg.quality = 压缩级别（1-9，默认 9）
op.bzip2.decompress.desc = Bzip2 解压
op.byteswap.desc = 按宽度字节组交换字节序（2/4/8；尾部字节保持不变）
op.chacha20.desc = ChaCha20 流加密（对称，再跑一次即解密）
op.chacha20.decrypt.desc = ChaCha20 流解密（按对称设计跑两次加密等价于解密）
op.charcode.decode.desc = 码点到 Unicode 字符（十进制/十六进制/八进制/二进制，容忍空白与逗号）
op.charcode.encode.desc = Unicode 字符转码点（空格分隔十进制）
op.count.desc = 统计子串出现次数（不重叠）
op.crc16.desc = CRC-16 校验和（变体：arc/modbus/ccitt-false/xmodem/usb/maxim/ccitt-true/kermit/x-25/dnp/buypass/gsm/dect-r/riello/spi-fujitsu/t10-dif/teledisk/genibus/ibm-3740/ibm-sdlc/mcrf4xx/custom；大端 2 字节；hex 请用 dpa:hex:encode）


op.crc32.desc = CRC-32 校验和（变体：pkzip/iso-hdlc/bzip2/mpeg-2/posix/xfer/jamcrc/c/d/q/xz/autosar/custom；大端 4 字节；hex 请用 dpa:hex:encode）


op.crc32c.desc = CRC-32C 校验和（变体：castagnoli/iscsi/nvme/custom；大端 4 字节；hex 请用 dpa:hex:encode）


op.csr.parse.desc = 解析 PKCS#10 证书签名请求（PEM 或 DER），输出 JSON 摘要：主题、公钥信息、签名算法与签名验证
op.csv.to-json.desc = 将 CSV（首行为表头）转换为紧凑 JSON 对象数组
op.datetime.delta.desc = 两个日期时间行之间的差值（秒 + 可读文本）
op.datetime.delta.arg.operation = 操作：diff（两行时间相减，默认）/ delta（第一行时间加第二行时长偏移）
op.datetime.parse.desc = 解析日期时间字符串（每行一个）并规范为 RFC3339 UTC
op.datetime.parse.arg.on_error = 无效行的错误处理：fail（默认，整批失败）/ skip（跳过无效行并在末尾附摘要）
op.datetime.translate.desc = 将日期时间字符串转换为目标 strftime 格式
op.decimal.decode.desc = 十进制转字节（空格/逗号分隔，取值 0-255，可配置分隔符）
op.decimal.encode.desc = 字节转十进制（可配置分隔符）
op.dedup.desc = 合并连续重复字节（游程去重）
op.defang.ip.desc = 去毒化 IPv4 地址（点号变为 [.]）
op.defang.ipv6.desc = 去毒化 IPv6 地址（冒号变为 [:]）
op.defang.url.desc = 去毒化 URL（http 变为 hxxp，点号变为 [.]）
op.deflate.compress.desc = 原始 DEFLATE 压缩（RFC 1951，无 zlib/gzip 包装）
op.deflate.decompress.desc = 原始 DEFLATE 解压（RFC 1951，无 zlib/gzip 包装）
op.des.decrypt.desc = DES 解密（模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
op.des.encrypt.desc = DES 加密（模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
op.des3.decrypt.desc = 3DES-EDE 解密（三密钥；模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
op.des3.encrypt.desc = 3DES-EDE 加密（三密钥；模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
op.distance.hamming.desc = 汉明距离：两个字节串的汉明距离（输入 A<sep>B）
op.distance.levenshtein.desc = 编辑距离：两个字符串的编辑距离（输入 A<sep>B），支持 Levenshtein / Damerau-Levenshtein / LCS 算法与可配置代价
op.drop.bytes.desc = 丢弃前 N 字节
op.ecdsa.verify.desc = 使用 PEM EC 公钥校验输入消息的 ECDSA 签名（DER 或原始 r||s）；输出 true 或 false
op.entropy.desc = 输入字节的香农熵（每字节比特数）
op.extract.dates.desc = 提取日期（ISO YYYY-MM-DD 及常见日/月/年格式）
op.extract.domains.desc = 提取域名（排除纯 IP 地址）
op.extract.emails.desc = 提取邮箱地址
op.extract.hashes.desc = 提取哈希摘要（长度档：0/32/40/56/64/96/128；输出附候选算法标注，标注不保证唯一）
op.extract.ips.desc = 提取 IP 地址（IPv4；可选 IPv6）
op.extract.mac.desc = 提取 MAC 地址（冒号/连字符/Cisco 点分格式）
op.extract.strings.desc = 提取可打印 ASCII 字符串（Unix strings 风格）
op.extract.urls.desc = 提取 URL
op.filetime.desc = 当前 Windows FILETIME（自 1601-01-01 起 100ns 计数；小端 hex）
op.filetime.arg.format = 输出格式：hex（小端，默认）/ dec
op.filetime.from.unix.desc = Unix 时间（s/ms/us）转 Windows FILETIME（自 1601-01-01 起 100ns 计数；小端 hex）
op.filetime.from.unix.arg.unit = 输入单位：s（默认）/ ms / us
op.filetime.from.unix.arg.format = 输出格式：hex（小端，默认）/ dec
op.filetime.to.date.desc = Windows FILETIME（小端 hex '0x..' 或十进制）转 UTC 日期字符串
op.filetime.to.date.arg.unit = 输入单位：ticks（默认）/ us / ms / s
op.filter.desc = 筛选包含子串的行
op.fletcher16.desc = Fletcher-16 校验和（大端 2 字节；hex 请用 dpa:hex:encode）


op.fletcher32.desc = Fletcher-32 校验和（大端 4 字节；hex 请用 dpa:hex:encode）


op.fletcher8.desc = Fletcher-8 校验和（半字节累加模 15，1 字节；hex 请用 dpa:hex:encode）


op.fletcher64.desc = Fletcher-64 校验和（小端字累加模 0xFFFFFFFF，8 字节；hex 请用 dpa:hex:encode）


op.fork.desc = Fork：按分隔符拆分并对每段运行剩余步骤（引擎级）
op.freq.distribution.desc = 字节频率分布（数量 + 百分比，降序）
op.gzip.compress.desc = gzip 压缩
op.gzip.decompress.desc = gzip 解压
op.head.desc = 取前 N 行
op.hex.decode.desc = 十六进制转字节（容忍空白，可配置分隔符）
op.hex.encode.desc = 字节转 hex（可配置分隔符、大小写与行宽换行）
op.hexdump.decode.desc = 十六进制转储解码（hexdump -C 行、逗号分隔字节或裸 hex）
op.hexdump.encode.desc = Hexdump 编码（hexdump -C 风格：偏移、十六进制、ASCII）
op.hkdf.desc = HKDF 密钥派生（RFC 5869）
op.hmac.desc = HMAC 摘要（SHA1/SHA256/SHA512）
op.html.decode.desc = 解码 HTML 实体（常用命名实体 + 数字实体 &#NN; &#xHH;；可切换模式）
op.html.encode.desc = 转义 HTML 特殊字符（& < > \\\\" '）
op.ic.desc = 重合指数（经典定义，0-26 标度）
op.json.get.desc = 按路径提取 JSON 字段
op.json.minify.desc = JSON 压缩为单行
op.json.pretty.desc = JSON 美化（2 空格缩进）
op.json.to-csv.desc = 将 JSON 对象数组转换为 CSV（键并集作为表头）
op.json.to-xml.desc = JSON 转 XML 文本（键 #text 为文本、@name 为属性、数组重复元素）
op.json.to-yaml.desc = JSON 文档转 YAML 文本
op.jwk.to.pem.desc = 将 JSON Web Key（JWK，RSA 或 EC 公钥）转换为 PEM 公钥
op.keccak.desc = Keccak 摘要（变体：224/256/384/512，默认 256；原始字节；hex 请用 dpa:hex:encode）


op.lzma.compress.desc = LZMA / XZ 压缩（格式：xz 或 lzma）
op.lzma.compress.arg.format = 容器格式（xz 或 lzma，默认 xz）
op.lzma.decompress.desc = LZMA / XZ 解压（格式：xz 或 lzma）
op.lzma.decompress.arg.format = 容器格式（xz 或 lzma，默认 xz）
op.lm-hash.desc = LM 哈希（大写 14 字节密钥的 DES；原始 16 字节；hex 请用 dpa:hex:encode）


op.lower.desc = ASCII 转小写（非 ASCII 字节不变）
op.md5.desc = MD5 摘要（raw 字节；hex 请用 dpa:hex:encode）

op.not.desc = 按位取反（反转每个字节）
op.nt-hash.desc = NT 哈希（密码 UTF-16LE 的 MD4；原始 16 字节；hex 请用 dpa:hex:encode）


op.octal.decode.desc = 八进制转字节（每字节 3 位，容忍空白与分隔符）
op.octal.encode.desc = 字节转八进制（每字节 3 位，可配置分隔符）
op.parse.ethernet.desc = 解析以太网帧：目的/源 MAC、EtherType、载荷长度
op.parse.ethernet.arg.input_type = 输入类型：auto / hex / raw（默认 raw）
op.parse.ipv4.desc = 解析 IPv4 数据包头：版本/IHL、TOS、总长度、标识、标志/分片偏移、TTL、协议、校验和、源/目的地址
op.parse.ipv4.arg.input_type = 输入类型：auto / hex / raw（默认 raw）
op.parse.ipv6.desc = 解析 IPv6 数据包头：版本、流量类别、流标签、载荷长度、下一跳头、跳数上限、源/目的地址
op.parse.tcp.desc = 解析 TCP 段头：源/目的端口、序号/确认号、数据偏移、标志、窗口、校验和、紧急指针
op.parse.tcp.arg.input_type = 输入类型：auto / hex / raw（默认 raw）
op.parse.tls.desc = 解析 TLS 记录（单包级）：每条记录的内容类型、版本、记录长度
op.parse.udp.desc = 解析 UDP 数据报头：源/目的端口、长度、校验和
op.parse.udp.arg.input_type = 输入类型：auto / hex / raw（默认 raw）
op.pbkdf2.desc = PBKDF2 密钥派生（HMAC-SHA1/SHA256/SHA512）
op.pem.desc = PEM 信封编解码：action=decode 去除 PEM 头并 base64 解码为原始 DER 字节；action=encode 将原始 DER 字节包装为 PEM 块（label 选择类型标签）
op.pem.to.jwk.desc = 将 PEM 公钥（RSA 或 EC）转换为 JSON Web Key（JWK）
op.pkcs1.to.pkcs8.desc = 将 PKCS#1 RSA PEM 密钥（RSA PRIVATE KEY / RSA PUBLIC KEY）转换为 PKCS#8 PEM（PRIVATE KEY / PUBLIC KEY）
op.pkcs8.to.pkcs1.desc = 将 PKCS#8 PEM 密钥（PRIVATE KEY / PUBLIC KEY，RSA）转换回 PKCS#1 PEM（RSA PRIVATE KEY / RSA PUBLIC KEY）
op.pubkey.extract.desc = 从 X.509 证书或 PKCS#10 CSR 中提取 SubjectPublicKeyInfo，输出为 PEM PUBLIC KEY 块
op.punycode.decode.desc = Punycode 解码（RFC 3492，容忍可选 xn-- 前缀）
op.punycode.encode.desc = Punycode 编码（RFC 3492，输入 UTF-8，可选 xn-- 前缀）
op.qp.decode.desc = Quoted-printable 解码（RFC 2045，移除软换行）
op.qp.encode.desc = Quoted-printable 编码（RFC 2045，=XX 转义，软换行）
op.random.desc = 生成随机原始字节（不可打印；可管道到 hex/utf8:escape 查看）
op.random.hex.desc = 生成随机字节（hex 字符串）
op.rc4.desc = RC4 流加密（对称，再跑一次即解密）
op.rc4.decrypt.desc = RC4 流解密（按对称设计跑两次加密等价于解密）
op.regex.match.desc = 正则匹配，返回全部命中（每行一条）
op.regex.replace.desc = 正则替换全部命中
op.replace.desc = 替换子串（UTF-8 字节序列）
op.reverse.desc = 反转字节序列
op.ripemd160.desc = RIPEMD-160 摘要（原始字节；hex 请用 dpa:hex:encode）


op.ripemd160.arg.size = 摘要大小：128 / 160 / 256 / 320（默认 160）
err.ripemd160.size = 未知 RIPEMD 大小：'{}'（可选 128 / 160 / 256 / 320）
op.rot13.bruteforce.desc = ROT13 暴力破解（全部 25 种凯撒位移；按文本评分取最优候选）
op.rot13.bruteforce.arg.top = 打印的候选位移数（默认 5）
op.rot13.bruteforce.arg.sample_length = 样本长度（字节，默认整个输入）
op.rot13.bruteforce.arg.sample_offset = 样本偏移（字节，默认 0）
op.rot13.bruteforce.arg.known_plaintext = 仅保留输出包含该子串的位移
op.rot13.desc = ROT13 凯撒位移（仅 ASCII 字母）
op.rot47.desc = ROT47 位移（ASCII 33..126）
op.rsa.verify.desc = 使用 PEM 公钥校验输入消息的 RSA 签名（PKCS#1 v1.5 或 PSS）；输出 true 或 false
op.sets.difference.desc = 差集：集合 A 减集合 B（输入 A<sep>B）
op.sets.intersection.desc = 交集：两个行集合取交集（输入 A<sep>B）
op.sets.union.desc = 并集：两个行集合取并集（输入 A<sep>B，行按原顺序保留）
op.sha1.desc = SHA-1 摘要（原始字节；hex 请用 dpa:hex:encode）


op.sha1.arg.rounds = 摘要迭代次数（对结果重复哈希 N 次，默认 1）
op.sha224.desc = SHA-224 摘要（原始字节；hex 请用 dpa:hex:encode）


op.sha224.arg.rounds = 摘要迭代次数（对结果重复哈希 N 次，默认 1）
op.sha256.desc = SHA-256 摘要（原始字节；hex 请用 dpa:hex:encode）


op.sha256.arg.rounds = 摘要迭代次数（对结果重复哈希 N 次，默认 1）
op.sha3.256.desc = SHA3-256 摘要（原始字节；hex 请用 dpa:hex:encode）


op.sha3.512.desc = SHA3-512 摘要（原始字节；hex 请用 dpa:hex:encode）


op.whirlpool.desc = Whirlpool 摘要（原始字节，ISO/IEC 10118-3；hex 请用 dpa:hex:encode）


op.sha384.desc = SHA-384 摘要（原始字节；hex 请用 dpa:hex:encode）


op.sha384.arg.rounds = 摘要迭代次数（对结果重复哈希 N 次，默认 1）
op.sha512.desc = SHA-512 摘要（原始字节；hex 请用 dpa:hex:encode）


op.sha512.arg.rounds = 摘要迭代次数（对结果重复哈希 N 次，默认 1）
op.shake.desc = SHAKE XOF 摘要（变体：128/256，默认 256；原始字节，输出指定长度；hex 请用 dpa:hex:encode）


op.similarity.jaccard.desc = Jaccard 相似度：两个行集合的 Jaccard 相似度（输入 A<sep>B）
op.sm3.desc = SM3 摘要（原始字节；GB/T 32905；hex 请用 dpa:hex:encode）


op.sm3.arg.rounds = 摘要迭代次数（对结果重复哈希 N 次，默认 1）
op.sm4.decrypt.desc = SM4 解密（模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
op.sm4.encrypt.desc = SM4 加密（模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
op.sm2.parse.desc = 解析 SM2 公钥（hex/raw；非压缩点或 x,y）
op.sm2.parse.arg.raw = 原始字节（压缩/非压缩点）
op.sm2.pubkey.extract.desc = 从私钥提取 SM2 公钥
op.sm2.key.parse.desc = 解析 SM2 私钥（hex/raw）
op.sm2.verify.desc = 验证 SM2 签名（SM2-with-SM3；默认 distid 1234567812345678）
op.sm2.verify.arg.key = 公钥（hex/raw）
op.sm2.verify.arg.digest = 待验证的消息摘要
op.sm2.verify.arg.signature = 签名（r||s，hex）
op.sm2.verify.arg.sig_format = 签名格式：der/rss
op.sm2.verify.arg.sig_type = 签名类型：sm2/sm3（基于 distid）
op.sm2.verify.arg.distid = 区分标识（默认 1234567812345678）
op.sort.desc = 按行字母序排序（alpha，默认）；numeric / ip / length / 原始字节序（bytes）通过 --type 选择
op.split.desc = 按分隔符拆分输入（每段一行）
op.ssdeep.desc = ssdeep 模糊哈希（CTPH；文本签名如 3:FJKKIUKact:FHIGi；与 libfuzzy 兼容）
op.ssdeep.compare.desc = 比较两个 ssdeep 模糊签名，返回 0-100 的相似度分数
op.ssdeep.compare.arg.delimiter = 分隔两个签名的分隔符
op.ssh.parse.desc = 解析公钥：支持 OpenSSH authorized_keys 行、RFC 4716 SSH2 块或 PKCS#8 SPKI（PEM/DER）格式，输出算法、位长、密钥字段及适用时的 SHA256 指纹，以 JSON 摘要呈现
op.strip.ethernet.desc = 剥离以太网头，保留载荷
op.strip.ipv4.desc = 剥离 IPv4 头，保留载荷
op.strip.ipv6.desc = 剥离 IPv6 头，保留载荷
op.strip.tcp.desc = 剥离 TCP 头，保留载荷
op.strip.udp.desc = 剥离 UDP 头，保留载荷
op.swapcase.desc = 交换 ASCII 字母大小写（a-z <=> A-Z；其它字节不变）
op.tail.desc = 取最后 N 行
op.take.bytes.desc = 取前 N 字节
op.tea.decode.desc = [已弃用别名] TEA 分组加密解码，请改用 dpa:tea:decrypt
op.tea.encrypt.desc = TEA 分组加密（64 位块；填充：zero/pkcs7/none）
op.tea.decrypt.desc = TEA 分组解密（64 位块；填充：zero/pkcs7/none）
op.tea.encode.desc = [已弃用别名] TEA 分组加密编码，请改用 dpa:tea:encrypt
op.timestamp.desc = 当前 Unix 时间戳（单位：s/ms/us/ns）
op.timestamp.to.date.desc = Unix 时间戳（秒）转 UTC 日期字符串
op.trim.desc = 去除首尾空白字节
op.unique.desc = 字节去重，保留首次出现顺序
op.upper.desc = ASCII 转大写（非 ASCII 字节不变）
op.url.decode.desc = URL 百分号解码（UTF-8）
op.url.encode.desc = URL 百分号编码（RFC 3986，非保留字符除外）
op.utf16.decode.desc = UTF-16 字节转 UTF-8（LE/BE，BOM 自动检测）
op.utf16.encode.desc = UTF-8 转 UTF-16 字节（LE/BE，可选 BOM）
op.utf8.escape.desc = 非打印字节百分号转义（%XX；'%' 转义为 '%25'），encode_all 时每个字节都转义；默认保留可打印 ASCII（含空格），与 url:encode 的转义范围不同
op.utf8.unescape.desc = 百分号转义（%XX）解码还原原始字节
op.uuid.desc = 生成 UUID（RFC 4122；--version 1|3|4|5，默认 4）
op.uuid.arg.version = UUID 版本：1（时间）/ 3（MD5 名称）/ 4（随机，默认）/ 5（SHA-1 名称）
op.uuid.arg.namespace = v3/v5 的命名空间 UUID（别名：dns / url / oid / x500）
op.uuid.arg.name = v3/v5 的名称
op.uuid4.desc = [已弃用别名] 同 dpa:uuid，请改用 dpa:uuid
op.uuid4.arg.version = UUID 版本：1（时间）/ 3（MD5 名称）/ 4（随机，默认）/ 5（SHA-1 名称）
op.uuid4.arg.namespace = v3/v5 的命名空间 UUID（别名：dns / url / oid / x500）
op.uuid4.arg.name = v3/v5 的名称
op.vigenere.decode.desc = 维吉尼亚密码解码（ASCII 字母，密钥循环）
op.vigenere.encode.desc = 维吉尼亚密码编码（ASCII 字母，密钥循环）
op.x509.desc = 解析 X.509 证书（PEM 或 DER）并输出 JSON 摘要：版本、序列号、签名算法、颁发者、有效期、主题、公钥信息、SAN
op.x509.arg.raw = 输出原始 DER 证书的十六进制而非解析后的 JSON 摘要（默认 false）
op.xml.to-json.desc = XML 文档转 JSON（属性 @name、文本 #text、重复标签转为数组）
op.xor.bruteforce.desc = XOR 暴力破解（单/双字节密钥，支持已知明文过滤；按文本评分取最优候选）
op.xor.desc = 与密钥循环异或
op.xtea.decode.desc = [已弃用别名] XTEA 分组加密解码，请改用 dpa:xtea:decrypt
op.xtea.encrypt.desc = XTEA 分组加密（64 位块；填充：zero/pkcs7/none）
op.xtea.decrypt.desc = XTEA 分组解密（64 位块；填充：zero/pkcs7/none）
op.xtea.encode.desc = [已弃用别名] XTEA 分组加密编码，请改用 dpa:xtea:encrypt
op.xxtea.decode.desc = [已弃用别名] XXTEA 分组加密解码，请改用 dpa:xxtea:decrypt
op.xxtea.encrypt.desc = XXTEA 分组加密（填充：zero/pkcs7/none）
op.xxtea.decrypt.desc = XXTEA 分组解密（填充：zero/pkcs7/none）
op.xxtea.encode.desc = [已弃用别名] XXTEA 分组加密编码，请改用 dpa:xxtea:encrypt
op.yaml.to-json.desc = YAML 文档转 JSON（解析标量/序列/映射）
op.zlib.compress.desc = zlib 压缩
op.zlib.decompress.desc = zlib 解压

# --- arg_descs (structured keys) ---
op.aes.decrypt.arg.aad = GCM 附加认证数据：'0x..' 按十六进制解析，否则按 UTF-8 字节；可选，默认空
op.aes.decrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零 16 字节块（gcm 默认 12 字节零 IV）
op.aes.decrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；16/24/32 字节对应 AES-128/192/256
op.aes.decrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr / gcm，默认 cbc
op.aes.decrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式与 gcm 忽略
op.aes.decrypt.arg.tag = GCM 认证标签（16 字节 hex，gcm 解密必需）
op.aes.encrypt.arg.aad = GCM 附加认证数据：'0x..' 按十六进制解析，否则按 UTF-8 字节；可选，默认空
op.aes.encrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零 16 字节块（gcm 默认 12 字节零 IV）
op.aes.encrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；16/24/32 字节对应 AES-128/192/256
op.aes.encrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr / gcm，默认 cbc
op.aes.encrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式与 gcm 忽略
op.base32.decode.arg.alphabet = 字母表预设（standard/extended-hex/crockford）或 32/33 字符；支持 A-Z2-7 等范围与 \- 转义（默认 standard）
op.base32.decode.arg.ignore_non_alphabet = 忽略字母表之外的字符而非报错（默认 false；空白始终忽略）
op.base32.decode.arg.strict_mode = 启用严格 Base32 规则：拒绝非法尾部长度（模 8 余 1/3/6）与非零尾部位（默认 false）
op.base32.encode.arg.alphabet = 字母表预设（standard/extended-hex/crockford）或 32/33 字符；支持 A-Z2-7 等范围与 \- 转义（默认 standard）
op.base32.encode.arg.pad = 填充字符（默认 '='；字母表为 33 字符时忽略）
op.base58.decode.arg.alphabet = 字母表预设（bitcoin/ripple）或 58 字符；支持范围写法如 A-Z0-9 与 \- 转义（默认 bitcoin）
op.base58.decode.arg.ignore_non_alphabet = 忽略字母表之外的字符而非报错（默认 false；空白始终忽略）
op.base58.encode.arg.alphabet = 字母表预设（bitcoin/ripple）或 58 字符；支持范围写法如 A-Z0-9 与 \- 转义（默认 bitcoin）
op.base62.decode.arg.alphabet = 字母表预设 standard 或 62 字符；支持 A-Z0-9 等范围展开与 \- 转义（默认 standard）
op.base62.decode.arg.ignore_non_alphabet = 忽略字母表之外的字符而非报错（默认 false；空白始终忽略）
op.base62.encode.arg.alphabet = 字母表预设 standard 或 62 字符；支持 A-Z0-9 等范围展开与 \- 转义（默认 standard）
op.base64.decode.arg.alphabet = 字母表预设（standard/url/url-safe/filename-safe/itoa64/xml/y64/z64/radix64/uuencode/xxencode/binhex/rot13/crypt/atom128/megan35/zong22/hazz15）或 64/65 字符；支持范围写法如 A-Za-z0-9+/ 及 \- 转义（默认 standard）
op.base64.decode.arg.ignore_non_alphabet = 忽略字母表之外的字符而非报错（默认 false；空白始终忽略）
op.base64.decode.arg.strict_mode = 启用严格 Base64 规则：拒绝 4n+1 长度以及错位/多余填充（默认 false）
op.base64.encode.arg.alphabet = 字母表预设（standard/url/url-safe/filename-safe/itoa64/xml/y64/z64/radix64/uuencode/xxencode/binhex/rot13/crypt/atom128/megan35/zong22/hazz15）或 64/65 字符；支持范围写法如 A-Za-z0-9+/ 及 \- 转义（默认 standard）
op.base64.encode.arg.pad = 填充字符（默认 '='；字母表为 65 字符时忽略）
op.base64.url.decode.arg.alphabet = 字母表预设（standard/url/url-safe/filename-safe/itoa64/xml/y64/z64/radix64/uuencode/xxencode/binhex/rot13/crypt/atom128/megan35/zong22/hazz15）或 64/65 字符；支持范围写法如 A-Za-z0-9+/ 及 \- 转义（默认 url）
op.base64.url.decode.arg.ignore_non_alphabet = 忽略字母表之外的字符而非报错（默认 false；空白始终忽略）
op.base64.url.decode.arg.strict_mode = 启用严格 Base64 规则：拒绝非法尾部长度与错位填充（默认 false）
op.base85.decode.arg.alphabet = 字母表预设 ascii85/z85/rfc1924 或 85 字符；支持 A-Z0-9 等范围展开与 \- 转义（默认 ascii85）
op.base85.decode.arg.ignore_non_alphabet = 忽略字母表之外的字符而非报错（默认 false；空白始终忽略）
op.base85.encode.arg.alphabet = 字母表预设 ascii85/z85/rfc1924 或 85 字符；支持 A-Z0-9 等范围展开与 \- 转义（默认 ascii85）
op.base85.encode.arg.remove_zeros = 将全零 4 字节组压缩为 'z'（默认 true）
op.binary.decode.arg.delimiter = 剥离输入分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 none；始终容忍空白）
op.binary.decode.arg.ignore_non_alphabet = 忽略 0/1 之外的字符而非报错（默认 false）
op.binary.encode.arg.delimiter = 字节分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 none）
op.bitwise.and.arg.key = 密钥字节（对输入循环使用）
op.bitwise.or.arg.key = 密钥字节（对输入循环使用）
op.bitwise.rotate-left.arg.bits = 循环移动位数，1-7
op.case.convert.desc = 将单词转换为目标大小写风格（camel/snake/kebab/pascal/title/constant）
op.case.convert.arg.style = 目标风格：camel（默认）/ snake / kebab / pascal / title / constant
op.atbash.desc = Atbash 替换密码（A-Z 映射为 Z-A，a-z 映射为 z-a）
op.remove.null.desc = 移除输入中的所有 NUL（0x00）字节
op.add.line_numbers.desc = 为每行添加右对齐行号
op.add.line_numbers.arg.offset = 行号偏移量，加在 1 起始编号上（默认 0）
op.add.line_numbers.arg.separator = 行号与行内容之间的分隔文本（默认单个空格）
op.substitute.desc = 按位置对应关系替换字节（明文字母表/密文字母表；支持 a-z 范围与换行、制表、反斜杠、十六进制转义）
op.substitute.arg.from = 要被替换的字节（支持范围与转义，如 a-zA-Z）
op.substitute.arg.to = 替换成的字节，与 from 按位置对应
op.substitute.arg.ignore_case = 忽略大小写映射并保留输入大小写，默认 false
op.bitwise.rotate-right.arg.bits = 循环移动位数，1-7
op.bitwise.shift-left.arg.bits = 移动位数，1-7
op.bitwise.shift-right.arg.bits = 移动位数，1-7
op.blowfish.decrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零 8 字节块
op.blowfish.decrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；4..56 字节
op.blowfish.decrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr，默认 cbc
op.blowfish.decrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式忽略
op.blowfish.encrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零 8 字节块
op.blowfish.encrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；4..56 字节
op.blowfish.encrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr，默认 cbc
op.blowfish.encrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式忽略
op.brotli.compress.arg.quality = Brotli 质量 0-11（默认：11）
op.byteswap.arg.width = 分组宽度（字节）：2/4/8，默认 4
op.chacha20.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 32 字节
op.chacha20.arg.nonce = Nonce：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 12 字节
op.charcode.decode.arg.base = 输入码点进制：十进制（默认；0x 前缀自动识别）、十六进制、八进制、二进制
op.charcode.decode.arg.delimiter = 剥离输入分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 space；始终容忍空白与逗号）
op.charcode.encode.arg.base = 输出进制：十进制（默认）、十六进制（0x 前缀）、八进制或二进制
op.charcode.encode.arg.delimiter = 码点分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 space）
op.count.arg.sub = 要统计的子串（字节序列）
op.crc16.arg.variant = CRC-16 变体：arc（默认）/ modbus / ccitt-false / xmodem / usb / maxim / ccitt-true / kermit / x-25 / dnp / buypass / gsm / dect-r / riello / spi-fujitsu / t10-dif / teledisk / genibus / ibm-3740 / ibm-sdlc / mcrf4xx / custom
op.crc32.arg.variant = CRC-32 变体：pkzip（默认）/ iso-hdlc / bzip2 / mpeg-2 / posix / xfer / jamcrc / c / d / q / xz / autosar / custom
op.crc32c.arg.variant = CRC-32C 变体：castagnoli（默认）/ iscsi / nvme / custom
op.crc.arg.width = 自定义 CRC 位宽：8/16/32/64（默认 16）
op.crc.arg.poly = 自定义 CRC 多项式（十六进制或十进制，默认 0）
op.crc.arg.init = 自定义 CRC 初值（十六进制或十进制，默认 0）
op.crc.arg.refin = 自定义 CRC 输入反射 true/false（默认 false）
op.crc.arg.refout = 自定义 CRC 输出反射 true/false（默认 false）
op.crc.arg.xorout = 自定义 CRC 最终异或值（十六进制或十进制，默认 0）
op.datetime.translate.arg.format = 目标 strftime 格式，如 %Y-%m-%d
op.datetime.translate.arg.on_error = 无效行的错误处理：fail（默认，整批失败）/ skip（跳过无效行并在末尾附摘要）
op.decimal.decode.arg.delimiter = 剥离输入分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 space；始终容忍空白）
op.decimal.decode.arg.ignore_non_alphabet = 忽略非数字字符而非报错（默认 false）
op.decimal.encode.arg.delimiter = 字节分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 space）
op.deflate.compress.arg.level = 压缩级别 0-9（默认：6）
op.des.decrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零块
op.des.decrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 8 字节
op.des.decrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr，默认 cbc
op.des.decrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式忽略
op.des.encrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零块
op.des.encrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 8 字节
op.des.encrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr，默认 cbc
op.des.encrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式忽略
op.des3.decrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零 8 字节块
op.des3.decrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 24 字节
op.des3.decrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr，默认 cbc
op.des3.decrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式忽略
op.des3.encrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零 8 字节块
op.des3.encrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 24 字节
op.des3.encrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr，默认 cbc
op.des3.encrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式忽略
op.distance.hamming.arg.separator = Separator between the two inputs, default '\\n\\n'
op.distance.levenshtein.arg.separator = Separator between the two inputs, default '\\n\\n'
op.distance.levenshtein.arg.algorithm = 算法：levenshtein（默认）/ damerau（相邻转置）/ lcs（最长公共子序列）
op.distance.levenshtein.arg.insert_cost = 每字符插入代价（默认 1；lcs 模式忽略）
op.distance.levenshtein.arg.delete_cost = 每字符删除代价（默认 1；lcs 模式忽略）
op.distance.levenshtein.arg.substitute_cost = 每字符替换代价（默认 1；lcs 模式忽略）
err.distance.levenshtein.algorithm_invalid = 无效的莱文斯坦算法：{}（可选：levenshtein / damerau / lcs）
err.distance.levenshtein.cost_invalid = 无效的 {} 值：{}（应为非负整数）
op.drop.bytes.arg.n = 丢弃的字节数
op.ecdsa.verify.arg.digest = 哈希：sha256（默认）/ sha384 / sha512
op.ecdsa.verify.arg.key = PEM EC 公钥（PUBLIC KEY，SPKI）
op.ecdsa.verify.arg.sig_format = 签名编码：hex（默认）/ base64
op.ecdsa.verify.arg.sig_type = 签名布局：der（默认）/ raw（r||s）
op.ecdsa.verify.arg.signature = 签名字节（hex 或 base64）
op.extract.ips.arg.ipv6 = 是否同时提取 IPv6 地址：true/false，默认 false
op.extract.strings.arg.min = 最小字符串长度，默认 4
op.extract.strings.arg.display_total = 显示提取到的项目总数：true/false，默认 false
op.extract.strings.arg.sort = 按字母顺序排序结果：true/false，默认 false
op.extract.strings.arg.unique = 去除重复结果：true/false，默认 false
op.extract.urls.arg.display_total = 显示提取到的项目总数：true/false，默认 false
op.extract.urls.arg.sort = 按字母顺序排序结果：true/false，默认 false
op.extract.urls.arg.unique = 去除重复结果：true/false，默认 false
op.extract.emails.arg.display_total = 显示提取到的项目总数：true/false，默认 false
op.extract.emails.arg.sort = 按字母顺序排序结果：true/false，默认 false
op.extract.emails.arg.unique = 去除重复结果：true/false，默认 false
op.extract.ips.arg.remove_local = 排除本地/私有 IPv4 地址：true/false，默认 false
op.extract.ips.arg.display_total = 显示提取到的项目总数：true/false，默认 false
op.extract.ips.arg.sort = 按字母顺序排序结果：true/false，默认 false
op.extract.ips.arg.unique = 去除重复结果：true/false，默认 false
op.extract.hashes.arg.length = 提取的哈希长度：0（全部）/32/40/56/64/96/128，默认 0
op.extract.hashes.arg.display_total = 显示提取到的项目总数：true/false，默认 false
op.extract.hashes.arg.sort = 按字母顺序排序结果：true/false，默认 false
op.extract.hashes.arg.unique = 去除重复结果：true/false，默认 false
op.extract.domains.arg.display_total = 显示提取到的项目总数：true/false，默认 false
op.extract.domains.arg.sort = 按字母顺序排序结果：true/false，默认 false
op.extract.domains.arg.unique = 去除重复结果：true/false，默认 false
op.extract.domains.arg.underscore = 允许以下划线开头的标签（DMARC/DKIM 记录）
op.extract.domains.arg.filter_ext_tlds = 过滤常见文件扩展名伪 TLD（如 app.js、style.css）：true/false，默认 true
op.extract.domains.arg.extra_tld_blacklist = 附加 TLD 黑名单（逗号分隔，忽略大小写）
op.extract.mac.arg.display_total = 显示提取到的项目总数：true/false，默认 false
op.extract.mac.arg.sort = 按字母顺序排序结果：true/false，默认 false
op.extract.mac.arg.unique = 去除重复结果：true/false，默认 false
op.extract.dates.arg.display_total = 显示提取到的项目总数：true/false，默认 false
op.extract.dates.arg.sort = 按字母顺序排序结果：true/false，默认 false
op.extract.dates.arg.unique = 去除重复结果：true/false，默认 false

op.filter.arg.sub = 保留行必须包含的子串
op.fork.arg.separator = 分段分隔符，默认换行
op.gzip.compress.arg.level = 压缩级别 0-9（默认：6）
op.gzip.compress.arg.filename = gzip 头文件名（FNAME），留空则不写文件名字段
op.gzip.compress.arg.comment = gzip 头注释（FCOMMENT），留空则不写注释字段
op.gzip.compress.arg.timestamp = gzip 头修改时间（Unix 秒），默认不写
op.gzip.compress.arg.os = gzip 操作系统字节 0-255（默认 255 未知）
op.gzip.compress.arg.fhcrc = 在头部包含文件校验和（FHCRC 标志）
op.head.arg.n = 要保留的行数
op.hex.decode.arg.delimiter = 剥离输入分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 none；始终容忍空白）
op.hex.decode.arg.ignore_non_alphabet = 丢弃所有非十六进制字符而非报错（默认 false）
op.hex.encode.arg.bytes_per_line = 每行字节数（换行）；0 禁用换行，允许 8..=64（默认 0）
op.hex.encode.arg.delimiter = 字节分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 none）
op.hex.encode.arg.uppercase = 输出大写 hex 数字（默认 false）
op.hexdump.decode.arg.delimiter = 输入布局：space（默认；带偏移/ASCII 的 hexdump -C 行）、comma（逗号分隔字节，可带 0x）或 none（连续 hex 流）
op.hexdump.encode.arg.bytes_per_line = 每行字节数，8..=64 且为 8 的倍数（默认 16）
op.hkdf.arg.hash = 哈希：sha1 / sha256 / sha512；默认 sha256
op.hkdf.arg.info = 上下文/信息字符串（UTF-8）；默认空
op.hkdf.arg.key = 输入密钥材料（IKM）：'0x..' 十六进制或 UTF-8；省略时使用操作输入
op.hkdf.arg.length = 输出密钥材料长度（字节）；默认 32
op.hkdf.arg.salt = 盐：'0x..' 十六进制或 UTF-8；空则按 HashLen 取零字节
op.hmac.arg.algo = 摘要算法：sha1 / sha256 / sha512 / sm3 / sha3-256 / sha3-512，默认 sha256
op.hmac.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节
op.html.decode.arg.mode = 实体范围：both（默认）、named（仅命名实体）或 numeric（仅数字实体）
op.html.encode.arg.encode_all = 将所有非 ASCII 字符编码为十进制数字实体（默认 false）
op.html.encode.arg.format = 实体格式：auto（默认）、named、numeric 或 hex
op.csv.to-json.arg.delimiter = 单元格分隔符（单个字节，默认 ,）
op.csv.to-json.arg.format = 输出格式：dict（默认）或 array
op.json.to-csv.arg.delimiter = 单元格分隔符（单个字节，默认 ,）
op.json.pretty.arg.indent = 缩进字符串、"tab" 或空格数 0-32（默认两个空格）
op.json.get.arg.path = 字段路径，如 a.b[0].c；支持 . 与 [N] 索引
op.keccak.arg.variant = 输出长度：224 / 256 / 384 / 512，默认 256
op.octal.decode.arg.delimiter = 剥离输入分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 none；始终容忍空白）
op.octal.decode.arg.ignore_non_alphabet = 忽略 0-7 之外的字符而非报错（默认 false）
op.octal.encode.arg.delimiter = 字节分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 none）
op.pbkdf2.arg.hash = PRF 哈希：sha1 / sha256 / sha512 / sm3 / sha3-256 / sha3-512；默认 sha256
op.pbkdf2.arg.iterations = 迭代次数；默认 10000
op.pbkdf2.arg.key = 口令/密码（UTF-8）；省略时使用操作输入
op.pbkdf2.arg.length = 派生密钥长度（字节）；默认 32
op.pbkdf2.arg.salt = 盐：'0x..' 按十六进制解析，否则按 UTF-8；默认空
op.pem.arg.action = PEM 操作：decode（默认）/ encode
op.pem.arg.label = PEM 编码时的类型标签（如 PUBLIC KEY / RSA PUBLIC KEY / CERTIFICATE），默认 PUBLIC KEY
op.punycode.decode.arg.use_prefix = 要求输入带 xn-- 前缀（严格模式；默认 false）
op.punycode.encode.arg.use_prefix = 添加 xn-- 前缀（默认：false）
op.qp.decode.arg.header_mode = 同时解码 RFC 2047 编码字（=?charset?Q/B?...?=，默认 false）
op.qp.encode.arg.encode_all = 即使非必需也将每个可打印 ASCII 字节做十六进制转义（默认 false）
op.qp.encode.arg.header_mode = RFC 2047 Q 编码：空格变为 '_'，仅 Q 安全字符直接输出（默认 false）
op.qp.encode.arg.wrap = 软换行的行宽；0 表示不换行（默认 76）
op.random.arg.bytes = 字节数，默认 16
op.random.hex.arg.bytes = 字节数，默认 16
op.rc4.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节
op.regex.match.arg.pattern = 正则表达式（Rust 语法）
op.regex.match.arg.builtin = 内置正则模板（ipv4/ipv6/email/url/domain/windows_path/unix_path/mac/uuid/date_ymd/date_dmy/date_mdy/strings）
op.regex.replace.arg.pattern = 正则表达式（Rust 语法）
op.regex.replace.arg.replacement = 替换文本，支持 \ 捕获组
op.regex.replace.arg.builtin = 内置正则模板（ipv4/ipv6/email/url/domain/windows_path/unix_path/mac/uuid/date_ymd/date_dmy/date_mdy/strings）
op.replace.arg.from = 被替换的内容
op.replace.arg.to = 替换成的内容
op.rot13.bruteforce.arg.top = 输出候选数量，默认 5
op.rsa.verify.arg.digest = 哈希：sha256（默认）/ sha384 / sha512
op.rsa.verify.arg.key = PEM RSA 公钥（PUBLIC KEY 或 RSA PUBLIC KEY）
op.rsa.verify.arg.padding = 签名填充：pkcs1v15（默认）/ pss
op.rsa.verify.arg.sig_format = 签名编码：hex（默认）/ base64
op.rsa.verify.arg.signature = 签名字节（hex 或 base64）
op.sets.difference.arg.separator = Separator between the two sets, default '\\n\\n'
op.sets.intersection.arg.separator = Separator between the two sets, default '\\n\\n'
op.sets.union.arg.separator = Separator between the two sets, default '\\n\\n'
op.sets.union.arg.item_separator = 集合内项目分隔符，默认 '\\n'
op.sets.intersection.arg.item_separator = 集合内项目分隔符，默认 '\\n'
op.sets.difference.arg.item_separator = 集合内项目分隔符，默认 '\\n'
op.bitwise.shift-right.arg.mode = 移位模式：logical / arithmetic，默认 logical
op.bitwise.rotate-left.arg.carry = 带进位旋转（9 位），默认 false
op.bitwise.rotate-right.arg.carry = 带进位旋转（9 位），默认 false
op.reverse.arg.mode = 模式：bytes / chars / lines，默认 bytes
op.upper.arg.mode = 模式：all / words / sentences / paragraphs，默认 all
op.rot13.arg.amount = 位移量 1-25，默认 13
op.rot13.arg.rot_lower = 旋转小写字母，默认 true
op.rot13.arg.rot_upper = 旋转大写字母，默认 true
op.rot13.arg.rot_numeric = 旋转数字，默认 false
op.rot47.arg.amount = 位移量，默认 47
op.sort.arg.type = 排序类型：alpha（默认）/ numeric / ip / length / bytes
op.unique.arg.separator = 行/项目去重的项目分隔符，默认空（字节级）
op.unique.arg.display_count = 为每个唯一项前置出现次数，默认 false
op.take.bytes.arg.start = 开始截取的字节偏移，默认 0
op.take.bytes.arg.per_line = 按行应用，默认 false
op.drop.bytes.arg.offset = 开始丢弃的字节偏移，默认 0
op.drop.bytes.arg.per_line = 按行应用，默认 false
op.split.arg.join = 拆分段之间的连接符，默认 '\\n'
op.filter.arg.regex = 将 sub 视为正则表达式，默认 false
op.filter.arg.invert = 保留不匹配的行，默认 false
err.missing_separator = 输入必须包含分隔两部分所需的分隔符
op.shake.arg.length = 输出长度（字节），默认 32
op.shake.arg.variant = SHAKE 变体：128 / 256，默认 256
op.similarity.jaccard.arg.separator = Separator between the two sets, default '\\n\\n'
op.sm4.decrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零块
op.sm4.decrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.sm4.decrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr，默认 cbc
op.sm4.decrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式忽略
op.sm4.encrypt.arg.iv = IV/计数器：'0x..' 按十六进制解析，否则按 UTF-8 字节；默认全零块
op.sm4.encrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.sm4.encrypt.arg.mode = 模式：ecb / cbc / cfb / ofb / ctr，默认 cbc
op.sm4.encrypt.arg.padding = 仅 ecb/cbc 的填充：pkcs7 / none，默认 pkcs7；流模式忽略
op.sm4.encrypt.arg.aad = 附加认证数据（仅 GCM）
op.sm4.decrypt.arg.aad = 附加认证数据（仅 GCM）
op.sm4.decrypt.arg.tag = 认证标签（仅 GCM）
op.sm4.mac.desc = SM4 MAC（CBC-MAC；需密钥；可选 IV）。安全警告：可变长度消息 + pkcs7 的 CBC-MAC 存在长度扩展/伪造风险，新代码请使用 dpa:sm4:cmac
op.sm4.cmac.desc = SM4 CMAC（GM/T 0005-2012，RFC 4493 构造；需密钥）
op.sm4.cmac.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.sm4.mac.arg.key = 密钥（16 字节）
op.sm4.mac.arg.iv = IV（16 字节，可选）
op.sm4.mac.arg.padding = 填充模式：zero/pkcs7/none
op.sm4.mac.help_note = 安全警告：可变长度消息（pkcs7 填充）的 CBC-MAC 存在长度扩展/伪造风险，新设计请优先使用 dpa:sm4:cmac。
op.split.arg.delimiter = 要拆分到的分隔符字符串
op.tail.arg.n = 要保留的行数
op.take.bytes.arg.n = 保留的字节数
op.tea.decode.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.tea.arg.padding = 填充模式：zero（默认）/ pkcs7 / none
op.tea.encode.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.tea.encrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.tea.decrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.timestamp.arg.unit = s / ms / us / ns；默认 s
op.url.decode.arg.use_plus = 将 '+' 解码为空格（application/x-www-form-urlencoded 表单语义，默认 false）
op.url.encode.arg.preserve_unreserved = 保留 RFC 3986 非保留字符 -._~ 不编码（默认 true）
op.url.encode.arg.use_plus = 将空格编码为 '+' 而非 %20（application/x-www-form-urlencoded；默认 false）
op.utf16.decode.arg.bom = 检测并剥离字节序标记 BOM（默认 true）
op.utf16.decode.arg.endian = 无 BOM 时的字节序：le/be（默认 le）
op.utf16.encode.arg.bom = 写入字节序标记 BOM（默认 false）
op.utf16.encode.arg.endian = 字节序：le/be（默认 le）
op.utf8.escape.arg.encode_all = 将包括可打印 ASCII 在内的每个字节都百分号编码（默认 false）
op.utf8.escape.arg.uppercase = 输出大写 hex 数字（默认 true）
op.vigenere.decode.arg.key = 密钥词（仅 ASCII 字母）
op.vigenere.encode.arg.key = 密钥词（仅 ASCII 字母）
op.xor.bruteforce.arg.key_length = 密钥长度（字节）：1 或 2，默认 1（2 字节暴力破解配合 sample 更快）
op.xor.bruteforce.arg.sample = 已知明文片段：'0x..' 按十六进制解析，否则按 UTF-8 字节；设置后仅保留与片段前缀匹配的密钥
op.xor.bruteforce.arg.top = 输出候选数量，默认 5
op.xor.bruteforce.arg.scheme = 解码方案：standard / input-differential / output-differential，默认 standard
op.xor.bruteforce.arg.null_preserving = 为 true 时跳过 0x00 及与当前密钥字节相同的字节（原样保留），默认 false
op.xor.bruteforce.arg.sample_offset = 已知明文片段与评分窗口在输入中的起始偏移（字节），默认 0
op.xor.bruteforce.arg.print_key = 为 true 时每个候选前输出密钥（0x..），默认 true
op.xor.bruteforce.arg.hex_output = 为 true 时解码结果以十六进制输出而非有损 UTF-8，默认 false
op.xor.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节
op.xor.arg.scheme = 方案：standard（循环密钥）/ input-delimited（密钥与输入按空白分段，第 i 段用第 i 个密钥）/ input-differential（密钥字节随输入字节更新）/ output-differential（密钥字节随输出字节更新）/ cascade（每字节与下一输入字节异或，末字节与 0 异或），默认 standard
op.xor.arg.null_preserving = 为 true 时跳过 0x00 及与当前密钥字节相同的字节（原样保留），默认 false
op.xtea.decode.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.xtea.encode.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.xtea.encrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.xtea.decrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.xxtea.decode.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.xxtea.encode.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.xxtea.encrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.xxtea.decrypt.arg.key = 密钥：'0x..' 按十六进制解析，否则按 UTF-8 字节；须为 16 字节
op.zlib.compress.arg.level = 压缩级别 0-9（默认：6）

# --- orphan legacy (old English-original keys no longer referenced by any op; kept as translation assets) ---
Base32 decode (RFC 4648, tolerant of whitespace) = Base32 解码（RFC 4648，容忍空白）
Base32 encode (RFC 4648 standard alphabet) = Base32 编码（RFC 4648 标准字母表）
Base64 URL-safe decode (tolerant of whitespace) = Base64 URL 安全解码（容忍空白）
Code points to Unicode chars (decimal or 0x hex, whitespace/comma tolerated) = 码点转 Unicode 字符（空格/逗号分隔十进制或 0x 十六进制）
Decode HTML entities (common named + numeric &#NN; &#xHH;) = 解码 HTML 实体（命名与数字 &#NN; &#xHH;）
Generate random bytes (hex output) = 生成随机字节（hex 输出）
Hexdump decode (parse hexdump -C style output back to bytes) = Hexdump 解码（解析 hexdump -C 风格输出还原为字节）
Separator between the two inputs, default '\n\n' = 两个输入之间的分隔符，默认空行
Separator between the two sets, default '\n\n' = 两个集合之间的分隔符，默认空行

# --- legacy ---
AES decrypt (mode: ecb/cbc/cfb/ofb/ctr; PKCS#7 for block modes) = AES 解密（模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
AES encrypt (mode: ecb/cbc/cfb/ofb/ctr; PKCS#7 for block modes) = AES 加密（模式：ecb/cbc/cfb/ofb/ctr；块模式用 PKCS#7）
Current Unix timestamp (seconds) = 当前 Unix 时间戳（秒）
DES decrypt (mode: ecb/cbc; PKCS#7 for block modes) = DES 解密（模式：ecb/cbc；块模式用 PKCS#7）
DES encrypt (mode: ecb/cbc; PKCS#7 for block modes) = DES 加密（模式：ecb/cbc；块模式用 PKCS#7）
Mode: ecb / cbc / ctr, default cbc = 模式：ecb / cbc / ctr，默认 cbc
Mode: ecb / cbc, default cbc = 模式：ecb / cbc，默认 cbc
SM4 decrypt (mode: ecb/cbc/ctr; PKCS#7 for block modes) = SM4 解密（模式：ecb/cbc/ctr；块模式用 PKCS#7）
SM4 encrypt (mode: ecb/cbc/ctr; PKCS#7 for block modes) = SM4 加密（模式：ecb/cbc/ctr；块模式用 PKCS#7）

# --- protocol (dpa:parse / dpa:strip) ---
Parse an Ethernet frame: destination/source MAC, EtherType, payload length = 解析以太网帧：目的/源 MAC、EtherType、载荷长度
Parse an IPv4 packet header: version/IHL, TOS, total length, ID, flags/fragment offset, TTL, protocol, checksum, src/dst = 解析 IPv4 数据包头：版本/IHL、TOS、总长度、标识、标志/分片偏移、TTL、协议、校验和、源/目的地址
Parse an IPv6 packet header: version, traffic class, flow label, payload length, next header, hop limit, src/dst = 解析 IPv6 数据包头：版本、流量类别、流标签、载荷长度、下一跳头、跳数上限、源/目的地址
Parse a TCP segment header: src/dst port, sequence/ack, data offset, flags, window, checksum, urgent pointer = 解析 TCP 段头：源/目的端口、序号/确认号、数据偏移、标志、窗口、校验和、紧急指针
Parse a UDP datagram header: src/dst port, length, checksum = 解析 UDP 数据报头：源/目的端口、长度、校验和
Parse TLS records (single packet): content type, version, record length for each record = 解析 TLS 记录（单包级）：每条记录的内容类型、版本、记录长度
Strip the Ethernet header and keep the payload = 剥离以太网头，保留载荷
Strip the IPv4 header and keep the payload = 剥离 IPv4 头，保留载荷
Strip the IPv6 header and keep the payload = 剥离 IPv6 头，保留载荷
Strip the TCP header and keep the payload = 剥离 TCP 头，保留载荷
Strip the UDP header and keep the payload = 剥离 UDP 头，保留载荷

# --- pubkey (dpa:pem / dpa:x509) ---
PEM envelope encode/decode: action=decode strips the PEM header and base64 to raw DER bytes; action=encode wraps raw DER bytes in a PEM block (label selects the type tag) = PEM 信封编解码：action=decode 去除 PEM 头并 base64 解码为原始 DER 字节；action=encode 将原始 DER 字节包装为 PEM 块（label 选择类型标签）
PEM action: decode (default) / encode = PEM 操作：decode（默认）/ encode
PEM type tag for encode (e.g. PUBLIC KEY / RSA PUBLIC KEY / CERTIFICATE), default PUBLIC KEY = PEM 编码时的类型标签（如 PUBLIC KEY / RSA PUBLIC KEY / CERTIFICATE），默认 PUBLIC KEY
Parse an X.509 certificate (PEM or DER) and emit a JSON summary: version, serial, signature algorithm, issuer, validity, subject, public key info, SAN = 解析 X.509 证书（PEM 或 DER）并输出 JSON 摘要：版本、序列号、签名算法、颁发者、有效期、主题、公钥信息、SAN

# --- pubkey v1.0 (format bridge + verify-only) ---
Convert a PKCS#1 RSA PEM key (RSA PRIVATE KEY / RSA PUBLIC KEY) into PKCS#8 PEM (PRIVATE KEY / PUBLIC KEY) = 将 PKCS#1 RSA PEM 密钥（RSA PRIVATE KEY / RSA PUBLIC KEY）转换为 PKCS#8 PEM（PRIVATE KEY / PUBLIC KEY）
Convert a PKCS#8 PEM key (PRIVATE KEY / PUBLIC KEY, RSA) back into PKCS#1 PEM (RSA PRIVATE KEY / RSA PUBLIC KEY) = 将 PKCS#8 PEM 密钥（PRIVATE KEY / PUBLIC KEY，RSA）转换回 PKCS#1 PEM（RSA PRIVATE KEY / RSA PUBLIC KEY）
Convert a PEM public key (RSA or EC) into a JSON Web Key (JWK) = 将 PEM 公钥（RSA 或 EC）转换为 JSON Web Key（JWK）
Convert a JSON Web Key (JWK, RSA or EC public key) into a PEM public key = 将 JSON Web Key（JWK，RSA 或 EC 公钥）转换为 PEM 公钥
Verify an RSA signature (PKCS#1 v1.5 or PSS) over the input message with a PEM public key; emits true or false = 使用 PEM 公钥校验输入消息的 RSA 签名（PKCS#1 v1.5 或 PSS）；输出 true 或 false
Verify an ECDSA signature (DER or raw r||s) over the input message with a PEM EC public key; emits true or false = 使用 PEM EC 公钥校验输入消息的 ECDSA 签名（DER 或原始 r||s）；输出 true 或 false
PEM RSA public key (PUBLIC KEY or RSA PUBLIC KEY) = PEM RSA 公钥（PUBLIC KEY 或 RSA PUBLIC KEY）
Signature padding: pkcs1v15 (default) / pss = 签名填充：pkcs1v15（默认）/ pss
Hash: sha256 (default) / sha384 / sha512 = 哈希：sha256（默认）/ sha384 / sha512
Signature bytes as hex or base64 = 签名字节（hex 或 base64）
Signature encoding: hex (default) / base64 = 签名编码：hex（默认）/ base64
PEM EC public key (PUBLIC KEY, SPKI) = PEM EC 公钥（PUBLIC KEY，SPKI）
Signature layout: der (default) / raw (r||s) = 签名布局：der（默认）/ raw（r||s）

Base62 encode (alphabet preset standard or 62 chars, range expansion) = Base62 编码（字母表预设 standard 或 62 字符，支持范围展开）
Base62 decode (custom alphabet, optional ignore-non-alphabet) = Base62 解码（自定义字母表，可忽略非字母表字符）
Alphabet preset (standard) or 62 chars; ranges like A-Z0-9 and \- escapes supported (default: standard) = 字母表预设 standard 或 62 字符；支持 A-Z0-9 等范围展开与 \- 转义（默认 standard）
Ascii85 encode (Adobe alphabet, z compression for zero groups) = Ascii85 编码（Adobe 字母表，零组使用 z 压缩）
Ascii85 decode (Adobe alphabet, z compression and whitespace supported) = Ascii85 解码（Adobe 字母表，支持 z 压缩与空白）
Alphabet preset (ascii85/z85/rfc1924) or 85 chars; ranges like A-Z0-9 and \- escapes supported (default: ascii85) = 字母表预设 ascii85/z85/rfc1924 或 85 字符；支持 A-Z0-9 等范围展开与 \- 转义（默认 ascii85）
Quoted-printable encode (RFC 2045, =XX escapes, soft line breaks) = Quoted-printable 编码（RFC 2045，=XX 转义，软换行）
Line width for soft breaks; 0 disables wrapping (default: 76) = 软换行的行宽；0 表示不换行（默认 76）
Quoted-printable decode (RFC 2045, soft line breaks removed) = Quoted-printable 解码（RFC 2045，移除软换行）
RFC 2047 Q-encoding: space becomes '_', only Q-safe characters pass through (default: false) = RFC 2047 Q 编码：空格变为 '_'，仅 Q 安全字符直接输出（默认 false）
Hex-escape every printable ASCII byte even when not strictly required (default: false) = 即使非必需也将每个可打印 ASCII 字节做十六进制转义（默认 false）
Punycode encode (RFC 3492, input UTF-8, optional xn-- prefix) = Punycode 编码（RFC 3492，输入 UTF-8，可选 xn-- 前缀）
Punycode decode (RFC 3492, optional xn-- prefix tolerated) = Punycode 解码（RFC 3492，容忍可选 xn-- 前缀）
Require the xn-- prefix (strict mode; default: false) = 要求输入带 xn-- 前缀（严格模式；默认 false）
Prepend the xn-- prefix (default: false) = 添加 xn-- 前缀（默认：false）
YAML document to JSON (parses scalars/sequences/mappings) = YAML 文档转 JSON（解析标量/序列/映射）
JSON document to YAML text = JSON 文档转 YAML 文本
XML document to JSON (attributes @name, text #text, repeated tags become arrays) = XML 文档转 JSON（属性 @name、文本 #text、重复标签转为数组）
JSON to XML text (keys #text for text, @name for attributes, arrays repeat elements) = JSON 转 XML 文本（键 #text 为文本、@name 为属性、数组重复元素）
Parse a PKCS#10 Certificate Signing Request (PEM or DER) and emit a JSON summary: subject, public key info, signature algorithm and signature validation = 解析 PKCS#10 证书签名请求（PEM 或 DER），输出 JSON 摘要：主题、公钥信息、签名算法与签名验证
Extract the SubjectPublicKeyInfo from an X.509 certificate or a PKCS#10 CSR and emit it as a PEM PUBLIC KEY block = 从 X.509 证书或 PKCS#10 CSR 中提取 SubjectPublicKeyInfo，输出为 PEM PUBLIC KEY 块
Decode a PEM envelope (or pass through raw DER) and emit the DER bytes as lowercase hex = 解码 PEM 外壳（或直接透传原始 DER），输出小写十六进制 DER 字节
Decode hex bytes and wrap them in a PEM block (label selects the type tag) = 解码十六进制字节并包装为 PEM 块（label 选择类型标签）
Parse an OpenSSH public key line (authorized_keys format, e.g. ssh-rsa/ssh-ed25519/ecdsa-sha2-*) and emit a JSON summary with algorithm, bits, key fields and SHA256 fingerprint = 解析 OpenSSH 公钥行（authorized_keys 格式，如 ssh-rsa/ssh-ed25519/ecdsa-sha2-*），输出算法、位数、密钥字段与 SHA256 指纹的 JSON 摘要
Parse a DER-encoded ASN.1 structure (raw DER bytes or hex) and emit a JSON tree of tags, lengths and values = 解析 DER 编码的 ASN.1 结构（原始 DER 字节或十六进制），输出标签、长度与值的 JSON 树
PEM type tag, e.g. PUBLIC KEY / CERTIFICATE, default PUBLIC KEY = PEM 类型标签，如 PUBLIC KEY / CERTIFICATE，默认 PUBLIC KEY

Byte separator: none/space/comma/semicolon/colon/newline/crlf (default: none) = 字节分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 none）
Byte separator: none/space/comma/semicolon/colon/newline/crlf (default: space) = 字节分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 space）
Strip input delimiter: none/space/comma/semicolon/colon/newline/crlf (default: none; whitespace is always tolerated) = 剥离输入分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 none；始终容忍空白）
Strip input delimiter: none/space/comma/semicolon/colon/newline/crlf (default: space; whitespace is always tolerated) = 剥离输入分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 space；始终容忍空白）
Code point separator: none/space/comma/semicolon/colon/newline/crlf (default: space) = 码点分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 space）
Output base: decimal (default) or hex (0x-prefixed) = 输出进制：decimal（默认）或 hex（0x 前缀）
Strip input delimiter: none/space/comma/semicolon/colon/newline/crlf (default: space; whitespace and comma are always tolerated) = 剥离输入分隔符：none/space/comma/semicolon/colon/newline/crlf（默认 space；始终容忍空白与逗号）
err.charcode_base_invalid = 无效的字符码进制：{}
Also encode every non-ASCII character as a decimal numeric entity (default: false) = 将所有非 ASCII 字符编码为十进制数字实体（默认 false）
err.html_encode_all_invalid = html encode_all 取值无效：{}
err.html_encode_format_invalid = html encode format 取值无效：{}（可选 auto / named / numeric / hex）
err.csv_format_invalid = csv format 取值无效：{}（可选 dict 或 array）
err.csv_delimiter_invalid = 分隔符必须是单个字节
err.json_indent_invalid = 缩进必须是字符串、tab 或 0-32 之间的数字
Percent-encode every byte including printable ASCII (default: false) = 将包括可打印 ASCII 在内的每个字节都百分号编码（默认 false）
err.utf8_encode_all_invalid = utf8 encode_all 取值无效：{}
Bytes per line, multiple of 8 in 8..=64 (default: 16) = 每行字节数，8..=64 且为 8 的倍数（默认 16）
err.hexdump_bpl_invalid = hexdump bytes_per_line 取值无效：{}
err.html_mode_invalid = html 解码模式取值无效：{}
err.hexdump_delim_invalid = hexdump 解码分隔符取值无效：{}
err.hex_bpl_invalid = hex bytes_per_line 取值无效：{}（0 或 8..=64）
Decode '+' as a space (application/x-www-form-urlencoded; default: false) = 将 '+' 解码为空格（application/x-www-form-urlencoded 表单语义，默认 false）
err.url_use_plus_invalid = url decode use_plus 取值无效：{}
Also decode RFC 2047 encoded-words (=?charset?Q/B?...?=; default: false) = 同时解码 RFC 2047 编码字（=?charset?Q/B?...?=，默认 false）
err.qp_header_mode_invalid = quoted-printable header_mode 取值无效：{}

UTF-8 to UTF-16 bytes (LE/BE, optional BOM) = UTF-8 转 UTF-16 字节（LE/BE，可选 BOM）
UTF-16 bytes to UTF-8 (LE/BE, BOM auto-detected) = UTF-16 字节转 UTF-8（LE/BE，BOM 自动检测）
err.utf16_endian_invalid = 无效的 UTF-16 字节序：'{}'（应为 le/be）
err.utf16_odd_length = UTF-16 解码失败：输入长度不是 2 的倍数
err.utf16_lone_surrogate = UTF-16 解码失败：孤立代理项（0x{}）缺少配对
err.utf16_invalid_code_point = UTF-16 解码失败：无效码点 U+{}
Byte order: le/be (default: le) = 字节序：le/be（默认 le）
Byte order when no BOM present: le/be (default: le) = 无 BOM 时的字节序：le/be（默认 le）
Write a byte order mark (default: false) = 写入字节序标记 BOM（默认 false）
Detect and strip a byte order mark (default: true) = 检测并剥离字节序标记 BOM（默认 true）

Output base: decimal (default), hex (0x-prefixed), octal or binary = 输出进制：十进制（默认）、十六进制（0x 前缀）、八进制或二进制
Code points to Unicode chars (decimal/hex/octal/binary, whitespace/comma tolerated) = 码点到 Unicode 字符（十进制/十六进制/八进制/二进制，容忍空白与逗号）
Input code point base: decimal (default; 0x-prefixed tokens auto-detected), hex, octal, binary = 输入码点进制：十进制（默认；0x 前缀自动识别）、十六进制、八进制、二进制
Decode HTML entities (common named + numeric &#NN; &#xHH;; mode-selectable) = 解码 HTML 实体（常用命名实体 + 数字实体 &#NN; &#xHH;；可切换模式）
Entity scope: both (default), named (HTML entities only) or numeric (&#NN; &#xHH; only) = 实体范围：both（默认）、named（仅命名实体）或 numeric（仅数字实体）
Hexdump decode (hexdump -C rows, comma-separated bytes or bare hex) = 十六进制转储解码（hexdump -C 行、逗号分隔字节或裸 hex）
Input layout: space (default; hexdump -C rows with offset/ASCII), comma (comma-separated bytes, 0x optional) or none (bare hex stream) = 输入布局：space（默认；带偏移/ASCII 的 hexdump -C 行）、comma（逗号分隔字节，可带 0x）或 none（连续 hex 流）

Ascii85 encode (Adobe alphabet, optional z compression for zero groups) = Ascii85 编码（Adobe 字母表，全零组可选 z 压缩）
Collapse all-zero 4-byte groups to 'z' (default: true) = 将全零 4 字节组压缩为 'z'（默认 true）
msg.op_level = 级别: {}
msg.op_input = 输入: {}
msg.op_output = 输出: {}

op.csv.to-json.arg.row-delimiter = 行分隔符：auto（默认，CRLF 或 LF）、lf 或 crlf
op.json.to-csv.arg.row-delimiter = 行分隔符：auto（默认）、lf 或 crlf
op.json.to-csv.arg.flatten = 将嵌套对象/数组展开为点路径列（true/false，默认 false）
err.csv_row_delimiter_invalid = 行分隔符取值无效：{}（可选 {}）
err.json_flatten_invalid = flatten 取值无效：{}（可选 true 或 false）

op.defang.url.arg.escape_dots = 转义点号（默认 true；false 保留点号原样）
op.defang.url.arg.escape_http = 转义 http（默认 true；http/https 变为 hxxp/hxxps）
op.defang.url.arg.escape_scheme = 转义 ://（默认 false；true 将 :// 变为 [://]）
op.defang.url.arg.process = 处理模式：everything（整个输入）/ urls（仅 URL 片段）/ domains（先 URL 再独立域名）
err.defang.flag_invalid = {name} 的布尔值无效：{v}（应为 true 或 false）
err.defang.process_invalid = 处理模式无效：{v}（应为 everything、urls 或 domains）

op.entropy.arg.scale = 熵标度：shannon（每字节比特数，默认）/ base10（每字节十进制位数）/ base256（每字节字节数）
op.freq.distribution.arg.show_zero = 是否列出计数为 0 的字节，默认 false
op.freq.distribution.arg.show_ascii = 是否显示 ASCII 字符列，默认 true
op.distance.hamming.arg.mode = 比较模式：bytes（默认，逐字节）/ bits（逐位汉明距离）
op.ssh.parse.arg.input_format = 输入格式：auto（默认，自动识别）/ openssh（authorized_keys 行）/ rfc4716（SSH2 PUBLIC KEY 块）/ pkcs8（PUBLIC KEY PEM 或 DER）
op.base45.encode.desc = Base45 编码（RFC 9285；用于二维码 / DCC 凭证）
op.ebcdic.encode.desc = EBCDIC 编码（ASCII/Latin-1 转 IBM cp037）
op.ebcdic.decode.desc = EBCDIC 解码（IBM cp037 转 ASCII/Latin-1）
op.base45.decode.desc = Base45 解码（RFC 9285；忽略空白字符）
op.base45.decode.arg.ignore_non_alphabet = 跳过非 Base45 字母表字符而不报错，默认 false
op.rail_fence.encode.desc = 栅栏密码编码（锯齿形换位）
op.rail_fence.decode.desc = 栅栏密码解码（锯齿形换位）
op.rail_fence.arg.rails = 栅栏行数（默认 3）
op.rail_fence.arg.offset = 布局前明文旋转偏移（默认 0）
op.luhn.desc = Luhn（模 10）校验：计算校验位、追加校验位或校验号码
op.luhn.arg.mode = 模式：check-digit（默认）/ append / verify

# generate family (de Bruijn / prime / HOTP / TOTP)
op.de.bruijn.desc = 生成数字 0..k-1 上的 De Bruijn 序列（FKM Lyndon 词构造）
op.de.bruijn.arg.size = 字母表大小 k（2-9）
op.de.bruijn.arg.order = 子串阶数 n（>= 2；k^n <= 50000）
op.prime.desc = 生成指定位长的随机可能素数（Miller-Rabin）
op.prime.arg.bits = 位长度（2-4096）
op.prime.arg.grade = 加密等级：40 轮代替 7 轮（默认 false）
op.prime.arg.format = 输出格式：decimal（默认）/ hex
op.hotp.desc = 生成基于 HMAC 的一次性密码（RFC 4226，SHA-1，动态截断）
op.hotp.arg.key = 共享密钥（base32，A-Z2-7）；留空则生成随机 20 字节密钥
op.hotp.arg.digits = 编码长度：6 / 7 / 8（默认 6）
op.hotp.arg.counter = 计数器值（默认 0）
op.totp.desc = 生成基于时间的一次性密码（RFC 6238，SHA-1）
op.totp.arg.key = 共享密钥（base32，A-Z2-7）；留空则生成随机 20 字节密钥
op.totp.arg.digits = 编码长度：6 / 7 / 8（默认 6）
op.totp.arg.period = 时间间隔 T1（秒，默认 30）
op.totp.arg.epoch = 时间偏移 T0（Unix 秒，默认 0）
op.totp.arg.time = 计算所用 Unix 时间（秒；默认当前时间）

err.range = 数值必须在 { $lo }..={ $hi } 范围内（实际为 { $value }）

err.env_var_missing = 步骤参数 '{}' 引用的环境变量 '{}' 不存在

# review P2 §3-G / §3-P8
err.plugin_bad_args = 插件 '{}' 的参数规格 JSON 无效：{}
err.plugin_hash_missing = 插件 '{}' 不在哈希清单中，已跳过（删除 {} 可重新生成）
err.plugin_hash_mismatch = 插件 '{}' 哈希与清单不符，已跳过（删除 {} 可重新生成）
msg.plugin_hash_generated = 插件哈希清单已写入 {}

# review P2 §3-F
err.input_too_large = 输入/输出超过 {} 字节上限（--max-input-bytes）
cli.max_input_bytes_help = 限制整缓冲输入与 Fork 输出累计的字节数（默认 268435456）

# review P3 G11
cli.verbose_help = 向 stderr 打印每步耗时与字节数
