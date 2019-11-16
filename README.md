# apksigner

This is golang's apksigner tool, source code reference golang.org\x\mobile\cmd\gomobile\build_androidapp.go

# example

jks to pem


keytool -v -importkeystore -srckeystore demo.jks -srcstoretype jks -srcstorepass demopwd -destkeystore demo.pfx -deststoretype pkcs12 -deststorepass demopwd -destkeypass demopwd
 
 
openssl pkcs12 -in demo.pfx -nocerts -nodes -out demo.key



key,err:=readPrivateKey();

err=apk.SignApk("xx.apk","xxsigned.apk",key);

if(err!=nil){
   fmt.Printf("err2:%v\r\n",err);
   return ;
}
