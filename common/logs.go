package common

import (
	"encoding/json"
	"fmt"
	"github.com/astaxie/beego/config"
	"github.com/astaxie/beego/logs"
)

func InitLogger() (err error) {
	BConfig, err := config.NewConfig("ini", "conf/app.conf")
	if err != nil {
		fmt.Println("config init error:", err)
		return
	}
	maxlines, lerr := BConfig.Int64("log::maxlines")
	if lerr != nil {
		maxlines = 20000
	}

	logConf := make(map[string]interface{})
	logConf["filename"] = BConfig.String("log::log_path")
	level, _ := BConfig.Int("log::log_level")
	logConf["level"] = level
	logConf["maxlines"] = maxlines

	confStr, err := json.Marshal(logConf)
	if err != nil {
		fmt.Println("marshal failed,err:", err)
		return
	}
	err = logs.SetLogger(logs.AdapterFile, string(confStr))
	if err != nil {
		fmt.Println("marshal failed,err:", err)
		return
	}
	logs.SetLogFuncCall(true)
	return
}

func LogInit() {
	err := InitLogger()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("log init success !")
}
