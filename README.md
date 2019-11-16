# apksigner

This is golang's apksigner tool, source code reference golang.org\x\mobile\cmd\gomobile\build_androidapp.go

# example

jks to pkcs12(pfx)


keytool -v -importkeystore -srckeystore demo.jks -srcstoretype jks -srcstorepass demopwd   -alias xxx -destkeystore demo.pfx -deststoretype pkcs12 -deststorepass demopwd -destkeypass demopwd
 
 



err=apk.SignApk("xx.apk","demo.pfx","demopwd","xxsigned.apk");

if(err!=nil){
   fmt.Printf("err2:%v\r\n",err);
   return ;
}
