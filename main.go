package main

import (
	"apksigner/apk"
	"flag"
	"fmt"
)
//jsk file path
var jksFile string
//store password
var storePwd string
//alias
var alias string
//key password
var keyPwd string

func main(){

	//这些参数必须有
	flag.StringVar(&jksFile,"jks","","jsk file path")
	flag.StringVar(&storePwd,"sPwd","","jks store password")
	flag.StringVar(&alias,"alias","","alias")
	flag.StringVar(&keyPwd,"kPwd","","key password")

	flag.Parse()


	err:=apk.SignApk("xx.apk","","","");
	if(err!=nil){
		fmt.Printf("err2:%v\r\n",err);
		return ;
	}
}






