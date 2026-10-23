package geo

import (
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

var zhRegions = display.Regions(language.SimplifiedChinese)

// countryNameZH 将 ISO 3166 国家代码转换为中文名称，使不同数据源的结果可以统一聚合展示。
func countryNameZH(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || zhRegions == nil {
		return ""
	}
	r, err := language.ParseRegion(code)
	if err != nil {
		return ""
	}
	name := zhRegions.Name(r)
	// 港澳台使用简称，与 ip2region 的展示保持一致
	switch code {
	case "HK":
		return "中国香港"
	case "MO":
		return "中国澳门"
	case "TW":
		return "中国台湾"
	}
	return name
}
