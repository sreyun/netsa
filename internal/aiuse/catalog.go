package aiuse

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// 服务类别。
const (
	CatChat    = "chat"    // 对话助手
	CatCoding  = "coding"  // 编程助手
	CatAPI     = "api"     // 模型接口（程序调用）
	CatImage   = "image"   // 图像视频生成
	CatAudio   = "audio"   // 语音、音乐、会议转写
	CatSearch  = "search"  // AI 搜索
	CatWriting = "writing" // 写作、翻译、办公
	CatAgent   = "agent"   // 智能体
	CatModel   = "model"   // 模型下载（本地部署模型的迹象）
	CatOther   = "other"
)

// CategoryLabel 是类别的中文名。
var CategoryLabel = map[string]string{CatChat: "对话助手", CatCoding: "编程助手", CatAPI: "模型接口", CatImage: "图像视频", CatAudio: "语音会议",
	CatSearch: "AI 搜索", CatWriting: "写作办公", CatAgent: "智能体", CatModel: "模型下载", CatOther: "其他"}

// 服务商所在地：境外服务的上传量单独统计（数据出境风险）。
const (
	RegionDomestic = "domestic"
	RegionOverseas = "overseas"
)

// RegionLabel 是所在地的中文名。
var RegionLabel = map[string]string{RegionDomestic: "境内", RegionOverseas: "境外", "": "未知"}

// 使用策略：由单位按 AI 使用管理制度设定，第一阶段只用于统计与展示（禁止类服务的使用者数量），不产生告警。
const (
	PolicyUnset    = ""
	PolicyAllow    = "allow"
	PolicyRestrict = "restrict"
	PolicyDeny     = "deny"
)

// PolicyLabel 是策略的中文名。
var PolicyLabel = map[string]string{PolicyUnset: "未设定", PolicyAllow: "允许", PolicyRestrict: "受限", PolicyDeny: "禁止"}

// 服务的来源。
const (
	SourceBuiltin = "builtin"
	SourceConfig  = "config"
	SourceUI      = "ui"
)

const (
	maxServices      = 1000
	maxDomainsPerSvc = 50
	maxDomainLen     = 253
)

// Service 是 AI 服务目录中的一项。
type Service struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Vendor   string   `json:"vendor,omitempty"`
	Category string   `json:"category"`
	Region   string   `json:"region,omitempty"`
	Policy   string   `json:"policy,omitempty"` // 生效的策略
	Domains  []string `json:"domains"`
	Note     string   `json:"note,omitempty"`
	Source   string   `json:"source"`
	// PolicyFrom 说明策略的来源：config（配置文件 ai_usage.policies 或服务定义）/ ui（页面设定）/ 空（未设定）
	PolicyFrom string `json:"policy_from,omitempty"`
}

// builtin 是内置的 AI 服务目录。只收录能按域名准确区分的服务：SaaS 里内嵌的 AI 功能（飞书、钉钉、WPS、Notion、
// Office 365 Copilot 等）与产品本身使用同一域名，按域名无法区分，不收录。域名按标签匹配（openai.com 匹配
// api.openai.com），含一个 * 的写法按前后缀匹配（bedrock-runtime.*.amazonaws.com）。
var builtin = []Service{
	// ---------- 境外 ----------
	{ID: "chatgpt", Name: "ChatGPT", Vendor: "OpenAI", Category: CatChat, Region: RegionOverseas, Domains: []string{"chatgpt.com", "chat.openai.com", "oaiusercontent.com"}},
	{ID: "openai-api", Name: "OpenAI API", Vendor: "OpenAI", Category: CatAPI, Region: RegionOverseas, Domains: []string{"api.openai.com"}},
	{ID: "claude", Name: "Claude", Vendor: "Anthropic", Category: CatChat, Region: RegionOverseas, Domains: []string{"claude.ai", "claude.com"}},
	{ID: "anthropic-api", Name: "Anthropic API", Vendor: "Anthropic", Category: CatAPI, Region: RegionOverseas, Domains: []string{"api.anthropic.com"}},
	{ID: "gemini", Name: "Gemini", Vendor: "Google", Category: CatChat, Region: RegionOverseas, Domains: []string{"gemini.google.com", "bard.google.com", "aistudio.google.com", "notebooklm.google.com"}},
	{ID: "gemini-api", Name: "Gemini API / Vertex AI", Vendor: "Google", Category: CatAPI, Region: RegionOverseas, Domains: []string{"generativelanguage.googleapis.com", "aiplatform.googleapis.com", "*-aiplatform.googleapis.com"}},
	{ID: "copilot", Name: "Microsoft Copilot", Vendor: "Microsoft", Category: CatChat, Region: RegionOverseas, Domains: []string{"copilot.microsoft.com", "sydney.bing.com"}},
	{ID: "github-copilot", Name: "GitHub Copilot", Vendor: "GitHub", Category: CatCoding, Region: RegionOverseas, Domains: []string{"githubcopilot.com", "copilot-proxy.githubusercontent.com"}},
	{ID: "azure-openai", Name: "Azure OpenAI", Vendor: "Microsoft", Category: CatAPI, Region: RegionOverseas, Domains: []string{"openai.azure.com"}},
	{ID: "bedrock", Name: "Amazon Bedrock", Vendor: "AWS", Category: CatAPI, Region: RegionOverseas, Domains: []string{"bedrock-runtime.*.amazonaws.com", "bedrock.*.amazonaws.com"}},
	{ID: "grok", Name: "Grok", Vendor: "xAI", Category: CatChat, Region: RegionOverseas, Domains: []string{"grok.com"}},
	{ID: "xai-api", Name: "xAI API", Vendor: "xAI", Category: CatAPI, Region: RegionOverseas, Domains: []string{"api.x.ai"}},
	{ID: "perplexity", Name: "Perplexity", Vendor: "Perplexity", Category: CatSearch, Region: RegionOverseas, Domains: []string{"perplexity.ai"}},
	{ID: "mistral", Name: "Mistral", Vendor: "Mistral AI", Category: CatChat, Region: RegionOverseas, Domains: []string{"chat.mistral.ai", "api.mistral.ai"}},
	{ID: "meta-ai", Name: "Meta AI", Vendor: "Meta", Category: CatChat, Region: RegionOverseas, Domains: []string{"meta.ai"}},
	{ID: "poe", Name: "Poe", Vendor: "Quora", Category: CatChat, Region: RegionOverseas, Domains: []string{"poe.com"}},
	{ID: "character", Name: "Character.AI", Vendor: "Character.AI", Category: CatChat, Region: RegionOverseas, Domains: []string{"character.ai"}},
	{ID: "openrouter", Name: "OpenRouter", Vendor: "OpenRouter", Category: CatAPI, Region: RegionOverseas, Domains: []string{"openrouter.ai"}},
	{ID: "groq", Name: "Groq", Vendor: "Groq", Category: CatAPI, Region: RegionOverseas, Domains: []string{"groq.com"}},
	{ID: "together", Name: "Together AI", Vendor: "Together", Category: CatAPI, Region: RegionOverseas, Domains: []string{"together.ai", "together.xyz"}},
	{ID: "cohere", Name: "Cohere", Vendor: "Cohere", Category: CatAPI, Region: RegionOverseas, Domains: []string{"cohere.ai", "cohere.com"}},
	{ID: "replicate", Name: "Replicate", Vendor: "Replicate", Category: CatAPI, Region: RegionOverseas, Domains: []string{"replicate.com", "replicate.delivery"}},
	{ID: "cursor", Name: "Cursor", Vendor: "Anysphere", Category: CatCoding, Region: RegionOverseas, Domains: []string{"cursor.sh", "cursor.com"}},
	{ID: "windsurf", Name: "Windsurf / Codeium", Vendor: "Codeium", Category: CatCoding, Region: RegionOverseas, Domains: []string{"codeium.com", "windsurf.com"}},
	{ID: "tabnine", Name: "Tabnine", Vendor: "Tabnine", Category: CatCoding, Region: RegionOverseas, Domains: []string{"tabnine.com"}},
	{ID: "replit", Name: "Replit", Vendor: "Replit", Category: CatCoding, Region: RegionOverseas, Domains: []string{"replit.com"}},
	{ID: "v0", Name: "v0", Vendor: "Vercel", Category: CatCoding, Region: RegionOverseas, Domains: []string{"v0.dev", "v0.app"}},
	{ID: "bolt", Name: "Bolt", Vendor: "StackBlitz", Category: CatCoding, Region: RegionOverseas, Domains: []string{"bolt.new"}},
	{ID: "lovable", Name: "Lovable", Vendor: "Lovable", Category: CatCoding, Region: RegionOverseas, Domains: []string{"lovable.dev"}},
	{ID: "manus", Name: "Manus", Vendor: "Manus", Category: CatAgent, Region: RegionOverseas, Domains: []string{"manus.im"}},
	{ID: "midjourney", Name: "Midjourney", Vendor: "Midjourney", Category: CatImage, Region: RegionOverseas, Domains: []string{"midjourney.com"}},
	{ID: "stability", Name: "Stability AI", Vendor: "Stability AI", Category: CatImage, Region: RegionOverseas, Domains: []string{"stability.ai"}},
	{ID: "runway", Name: "Runway", Vendor: "Runway", Category: CatImage, Region: RegionOverseas, Domains: []string{"runwayml.com"}},
	{ID: "elevenlabs", Name: "ElevenLabs", Vendor: "ElevenLabs", Category: CatAudio, Region: RegionOverseas, Domains: []string{"elevenlabs.io"}},
	{ID: "suno", Name: "Suno", Vendor: "Suno", Category: CatAudio, Region: RegionOverseas, Domains: []string{"suno.com", "suno.ai"}},
	{ID: "otter", Name: "Otter.ai", Vendor: "Otter.ai", Category: CatAudio, Region: RegionOverseas, Domains: []string{"otter.ai"}},
	{ID: "fireflies", Name: "Fireflies.ai", Vendor: "Fireflies", Category: CatAudio, Region: RegionOverseas, Domains: []string{"fireflies.ai"}},
	{ID: "deepl", Name: "DeepL", Vendor: "DeepL", Category: CatWriting, Region: RegionOverseas, Domains: []string{"deepl.com"}},
	{ID: "grammarly", Name: "Grammarly", Vendor: "Grammarly", Category: CatWriting, Region: RegionOverseas, Domains: []string{"grammarly.com", "grammarly.io"}},
	{ID: "gamma", Name: "Gamma", Vendor: "Gamma", Category: CatWriting, Region: RegionOverseas, Domains: []string{"gamma.app"}},
	{ID: "you", Name: "You.com", Vendor: "You.com", Category: CatSearch, Region: RegionOverseas, Domains: []string{"you.com"}},
	{ID: "phind", Name: "Phind", Vendor: "Phind", Category: CatSearch, Region: RegionOverseas, Domains: []string{"phind.com"}},
	{ID: "huggingface", Name: "Hugging Face", Vendor: "Hugging Face", Category: CatModel, Region: RegionOverseas, Domains: []string{"huggingface.co", "hf.co"}},
	{ID: "ollama", Name: "Ollama 模型库", Vendor: "Ollama", Category: CatModel, Region: RegionOverseas, Domains: []string{"ollama.com", "ollama.ai"}},
	{ID: "lmstudio", Name: "LM Studio", Vendor: "LM Studio", Category: CatModel, Region: RegionOverseas, Domains: []string{"lmstudio.ai"}},
	{ID: "civitai", Name: "Civitai", Vendor: "Civitai", Category: CatModel, Region: RegionOverseas, Domains: []string{"civitai.com"}},

	// ---------- 境内 ----------
	{ID: "deepseek", Name: "DeepSeek", Vendor: "深度求索", Category: CatChat, Region: RegionDomestic, Domains: []string{"chat.deepseek.com"}},
	{ID: "deepseek-api", Name: "DeepSeek API", Vendor: "深度求索", Category: CatAPI, Region: RegionDomestic, Domains: []string{"api.deepseek.com"}},
	{ID: "kimi", Name: "Kimi", Vendor: "月之暗面", Category: CatChat, Region: RegionDomestic, Domains: []string{"kimi.com", "kimi.moonshot.cn"}},
	{ID: "moonshot-api", Name: "Moonshot API", Vendor: "月之暗面", Category: CatAPI, Region: RegionDomestic, Domains: []string{"api.moonshot.cn", "api.moonshot.ai"}},
	{ID: "tongyi", Name: "通义千问", Vendor: "阿里巴巴", Category: CatChat, Region: RegionDomestic, Domains: []string{"tongyi.aliyun.com", "tongyi.com", "chat.qwen.ai"}},
	{ID: "dashscope", Name: "阿里云百炼 / DashScope", Vendor: "阿里云", Category: CatAPI, Region: RegionDomestic, Domains: []string{"dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com", "bailian.console.aliyun.com"}},
	{ID: "lingma", Name: "通义灵码", Vendor: "阿里云", Category: CatCoding, Region: RegionDomestic, Domains: []string{"lingma.aliyun.com"}},
	{ID: "modelscope", Name: "魔搭社区", Vendor: "阿里巴巴", Category: CatModel, Region: RegionDomestic, Domains: []string{"modelscope.cn"}},
	{ID: "yiyan", Name: "文心一言", Vendor: "百度", Category: CatChat, Region: RegionDomestic, Domains: []string{"yiyan.baidu.com"}},
	{ID: "qianfan", Name: "百度千帆", Vendor: "百度", Category: CatAPI, Region: RegionDomestic, Domains: []string{"qianfan.baidubce.com"}},
	{ID: "comate", Name: "文心快码 Comate", Vendor: "百度", Category: CatCoding, Region: RegionDomestic, Domains: []string{"comate.baidu.com"}},
	{ID: "doubao", Name: "豆包", Vendor: "字节跳动", Category: CatChat, Region: RegionDomestic, Domains: []string{"doubao.com"}},
	{ID: "ark", Name: "火山方舟", Vendor: "字节跳动", Category: CatAPI, Region: RegionDomestic, Domains: []string{"ark.*.volces.com"}},
	{ID: "trae", Name: "Trae / MarsCode", Vendor: "字节跳动", Category: CatCoding, Region: RegionDomestic, Domains: []string{"trae.ai", "trae.cn", "marscode.cn", "marscode.com"}},
	{ID: "jimeng", Name: "即梦", Vendor: "字节跳动", Category: CatImage, Region: RegionDomestic, Domains: []string{"jimeng.jianying.com"}},
	{ID: "yuanbao", Name: "腾讯元宝", Vendor: "腾讯", Category: CatChat, Region: RegionDomestic, Domains: []string{"yuanbao.tencent.com"}},
	{ID: "hunyuan", Name: "腾讯混元 API", Vendor: "腾讯", Category: CatAPI, Region: RegionDomestic, Domains: []string{"hunyuan.tencentcloudapi.com", "api.hunyuan.cloud.tencent.com"}},
	{ID: "codebuddy", Name: "腾讯云 AI 代码助手", Vendor: "腾讯", Category: CatCoding, Region: RegionDomestic, Domains: []string{"copilot.tencent.com"}},
	{ID: "chatglm", Name: "智谱清言", Vendor: "智谱", Category: CatChat, Region: RegionDomestic, Domains: []string{"chatglm.cn", "chat.z.ai"}},
	{ID: "bigmodel", Name: "智谱开放平台", Vendor: "智谱", Category: CatAPI, Region: RegionDomestic, Domains: []string{"open.bigmodel.cn", "api.z.ai"}},
	{ID: "codegeex", Name: "CodeGeeX", Vendor: "智谱", Category: CatCoding, Region: RegionDomestic, Domains: []string{"codegeex.cn"}},
	{ID: "xinghuo", Name: "讯飞星火", Vendor: "科大讯飞", Category: CatChat, Region: RegionDomestic, Domains: []string{"xinghuo.xfyun.cn"}},
	{ID: "spark-api", Name: "讯飞星火 API", Vendor: "科大讯飞", Category: CatAPI, Region: RegionDomestic, Domains: []string{"spark-api.xf-yun.com", "spark-api-open.xf-yun.com"}},
	{ID: "minimax", Name: "MiniMax / 海螺 AI", Vendor: "MiniMax", Category: CatChat, Region: RegionDomestic, Domains: []string{"hailuoai.com", "minimaxi.com", "api.minimax.chat"}},
	{ID: "baichuan", Name: "百川", Vendor: "百川智能", Category: CatChat, Region: RegionDomestic, Domains: []string{"baichuan-ai.com"}},
	{ID: "stepfun", Name: "跃问 / 阶跃星辰", Vendor: "阶跃星辰", Category: CatChat, Region: RegionDomestic, Domains: []string{"yuewen.cn", "stepfun.com"}},
	{ID: "lingyi", Name: "零一万物", Vendor: "零一万物", Category: CatAPI, Region: RegionDomestic, Domains: []string{"lingyiwanwu.com"}},
	{ID: "siliconflow", Name: "硅基流动", Vendor: "硅基流动", Category: CatAPI, Region: RegionDomestic, Domains: []string{"siliconflow.cn", "siliconflow.com"}},
	{ID: "metaso", Name: "秘塔 AI 搜索", Vendor: "秘塔", Category: CatSearch, Region: RegionDomestic, Domains: []string{"metaso.cn"}},
	{ID: "tiangong", Name: "天工 AI", Vendor: "昆仑万维", Category: CatChat, Region: RegionDomestic, Domains: []string{"tiangong.cn"}},
	{ID: "kling", Name: "可灵", Vendor: "快手", Category: CatImage, Region: RegionDomestic, Domains: []string{"klingai.com", "klingai.kuaishou.com"}},
	{ID: "hf-mirror", Name: "Hugging Face 镜像站", Vendor: "社区", Category: CatModel, Region: RegionDomestic, Domains: []string{"hf-mirror.com"}},
}

// Builtin 返回内置目录的副本。
func Builtin() []Service {
	out := make([]Service, len(builtin))
	for i, s := range builtin {
		s.Domains = append([]string(nil), s.Domains...)
		s.Source = SourceBuiltin
		out[i] = s
	}
	return out
}

// normDomain 规范化目录中的域名：小写、去掉前导 *. 与结尾的点；只允许字母、数字、- _ . 与最多一个 *（前后缀匹配）。
func normDomain(v string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(v))
	d = strings.TrimSuffix(d, ".")
	for strings.HasPrefix(d, "*.") { // *.example.com 与 example.com 相同（按标签匹配，含子域名）
		d = d[2:]
	}
	d = strings.TrimPrefix(d, ".")
	if d == "" {
		return "", errors.New("域名为空")
	}
	if len(d) > maxDomainLen {
		return "", fmt.Errorf("域名过长：%s", v)
	}
	if strings.Count(d, "*") > 1 {
		return "", fmt.Errorf("域名最多包含一个 *：%s", v)
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '*') {
			return "", fmt.Errorf("域名包含无效字符：%s", v)
		}
	}
	if !strings.Contains(strings.Replace(d, "*", "", 1), ".") {
		return "", fmt.Errorf("域名至少包含两级（如 example.com）：%s", v)
	}
	if strings.Contains(d, "..") {
		return "", fmt.Errorf("域名格式不正确：%s", v)
	}
	if tooBroad[d] {
		return "", fmt.Errorf("域名过于宽泛（%s 下还有大量与 AI 无关的业务），请填写具体的子域名", v)
	}
	if g := strings.IndexByte(d, '*'); g >= 0 && (len(d)-1 < 10 || !strings.Contains(d[g+1:], ".")) {
		return "", fmt.Errorf("含 * 的域名过于宽泛：%s", v)
	}
	return d, nil
}

// tooBroad 是不能整体登记为 AI 服务的域名：公共后缀，以及其下大部分业务与 AI 无关的平台主域名。
// 这些平台上的 AI 服务要登记具体的子域名（如 gemini.google.com、dashscope.aliyuncs.com）。
var tooBroad = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true, "co.uk": true, "co.jp": true, "com.hk": true, "com.tw": true,
	"google.com": true, "googleapis.com": true, "gstatic.com": true, "microsoft.com": true, "azure.com": true, "windows.net": true, "bing.com": true,
	"live.com": true, "office.com": true, "github.com": true, "githubusercontent.com": true, "amazonaws.com": true, "amazon.com": true,
	"cloudflare.com": true, "apple.com": true, "icloud.com": true, "baidu.com": true, "baidubce.com": true, "qq.com": true, "tencent.com": true,
	"tencentcloudapi.com": true, "aliyun.com": true, "aliyuncs.com": true, "alibaba.com": true, "taobao.com": true, "volces.com": true,
	"bytedance.com": true, "douyin.com": true, "jianying.com": true, "kuaishou.com": true, "xfyun.cn": true, "huaweicloud.com": true,
}

// prepare 校验并规范化服务定义。
func (s *Service) prepare() error {
	s.ID = strings.TrimSpace(s.ID)
	s.Name = cleanText(s.Name, 60)
	s.Vendor = cleanText(s.Vendor, 40)
	s.Note = cleanText(s.Note, 200)
	if s.Name == "" {
		return errors.New("服务名称不能为空")
	}
	if s.ID == "" || len(s.ID) > 64 {
		return errors.New("服务编号无效")
	}
	for i := 0; i < len(s.ID); i++ {
		c := s.ID[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("服务编号只能包含字母、数字与 - _ .：%s", s.ID)
		}
	}
	if s.Category == "" {
		s.Category = CatOther
	}
	if _, ok := CategoryLabel[s.Category]; !ok {
		return fmt.Errorf("未知的服务类别 %q（可选 %s）", s.Category, strings.Join(sortedKeys(CategoryLabel), " / "))
	}
	if _, ok := RegionLabel[s.Region]; !ok {
		return fmt.Errorf("未知的服务所在地 %q（可选 domestic / overseas）", s.Region)
	}
	if err := validPolicy(s.Policy); err != nil {
		return err
	}
	if len(s.Domains) == 0 {
		return errors.New("至少填写一个域名")
	}
	if len(s.Domains) > maxDomainsPerSvc {
		return fmt.Errorf("域名最多 %d 个", maxDomainsPerSvc)
	}
	seen := map[string]bool{}
	var ds []string
	for _, v := range s.Domains {
		d, err := normDomain(v)
		if err != nil {
			return err
		}
		if !seen[d] {
			seen[d] = true
			ds = append(ds, d)
		}
	}
	s.Domains = ds
	return nil
}

func validPolicy(p string) error {
	if _, ok := PolicyLabel[p]; !ok {
		return fmt.Errorf("未知的使用策略 %q（可选 allow / restrict / deny，留空为未设定）", p)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	var out []string
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// cleanText 去掉控制字符并截断。
func cleanText(s string, limit int) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > limit {
		s = string([]rune(s)[:limit])
	}
	return s
}

// glob 是含一个 * 的域名：按前缀与后缀匹配。
type glob struct {
	prefix, suffix string
	svc            string
}

// matcher 是按域名查找服务的只读索引，目录变化时整体替换。
type matcher struct {
	exact map[string]string // 域名 → 服务编号（按标签匹配）
	globs []glob
}

func newMatcher(list []*Service) *matcher {
	m := &matcher{exact: map[string]string{}}
	for _, s := range list {
		for _, d := range s.Domains {
			if i := strings.IndexByte(d, '*'); i >= 0 {
				m.globs = append(m.globs, glob{prefix: d[:i], suffix: d[i+1:], svc: s.ID})
				continue
			}
			if _, dup := m.exact[d]; !dup { // 同一域名出现在多个服务中时，先登记的生效
				m.exact[d] = s.ID
			}
		}
	}
	return m
}

// match 返回域名对应的服务编号：从完整域名逐级向上查找，最具体的登记优先；都没有时再按前后缀匹配。
func (m *matcher) match(name string) string {
	if m == nil || name == "" {
		return ""
	}
	for d := name; ; {
		if id, ok := m.exact[d]; ok {
			return id
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	for _, g := range m.globs {
		if len(name) > len(g.prefix)+len(g.suffix) && strings.HasPrefix(name, g.prefix) && strings.HasSuffix(name, g.suffix) {
			return g.svc
		}
	}
	return ""
}

// normName 把日志中的域名（DNS 查询名、SNI、Host 头）规范化为小写、无端口、无结尾点；格式不像域名时返回空串。
func normName(v string) string {
	if v == "" || len(v) > maxDomainLen+6 {
		return ""
	}
	if v[0] == '[' { // [IPv6]:port
		return ""
	}
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		if strings.IndexByte(v, ':') != i { // 裸 IPv6 地址
			return ""
		}
		v = v[:i]
	}
	v = strings.TrimSuffix(v, ".")
	lower := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		case c >= 'A' && c <= 'Z':
			lower = true
		default:
			return ""
		}
	}
	if lower {
		v = strings.ToLower(v)
	}
	if !strings.Contains(v, ".") || len(v) > maxDomainLen {
		return ""
	}
	return v
}
