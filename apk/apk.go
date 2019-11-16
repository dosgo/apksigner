package apk

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"github.com/fullsailor/pkcs7"
	"golang.org/x/crypto/pkcs12"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)



/*
 apk   apk file path
 outapkfile out apk file path
 priv privateKey
*/
func SignApk(putApkFile string,pfxFile string,pfxPwd string,outApkFile string) (err error){

	//tmep path
	tmpPath,err:=ioutil.TempDir("","apksigned");

	os.MkdirAll(tmpPath+"",os.ModePerm)

	mfName:=tmpPath+"/MANIFEST.MF"
	sfName:=tmpPath+"/CERT.SF"
	var manifestMf,certSf,certRsa *os.File
	if manifestMf, err = os.Create(mfName); err != nil{
		return
	}
	if certSf, err = os.Create(sfName); err != nil{
		return
	}
	if certRsa, err = os.Create(tmpPath+"/CERT.RSA"); err != nil{
		return
	}

	var reader *zip.ReadCloser
	if reader, err = zip.OpenReader(putApkFile); err != nil{
		return err
	}
	defer reader.Close()
	mm_header := "Manifest-Version: 1.0\r\nBuilt-By: Generated-by-ADT\r\nCreated-By: Android Gradle 3.2.0\r\n\r\n"
	mm_dex_header := "Manifest-Version: 1.0\r\nDex-Location: classes.dex\r\nBuilt-By: Generated-by-ADT\r\nCreated-By: Android Gradle 3.2.0\r\n\r\n"

	//判断文件是否有dex；
	hasDex:=false
	for _, file := range reader.File {
		if file.Name == "classes.dex" {
			hasDex = true
			break
		}
	}
	if(hasDex){
		manifestMf.Write([]byte(mm_dex_header))
	}else {
		manifestMf.Write([]byte(mm_header))
	}
	//sf文件内容
	certBody := new(bytes.Buffer)
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "META-INF"){
			continue
		}
		if strings.HasSuffix(file.Name, "/"){
			continue
		}
		file_name := "Name: "+file.Name
		if len(file_name) <= 70{
			file_name=file_name+"\r\n"
		}else{
			file_name=file_name[0:70]+"\r\n"+" "+file_name[70:]+"\r\n"
		}
		manifestMf.Write([]byte(file_name))
		if rc, e := file.Open(); e != nil{
			err = e
			return
		}else{
			sha1h := sha1.New()
			if _, err = io.Copy(sha1h,rc);err!=nil{
				return
			}
			sha1_data := base64.StdEncoding.EncodeToString(sha1h.Sum(nil))
			mfItem:="SHA1-Digest: "+sha1_data+"\r\n\r\n";
			manifestMf.Write([]byte(mfItem))
			rc.Close()

			//计算mf的值
			cHash := sha1.New()
			fmt.Fprintf(cHash, "%s%s", file_name, mfItem)
			ch := base64.StdEncoding.EncodeToString(cHash.Sum(nil))
			fmt.Fprintf(certBody, "%sSHA1-Digest: %s\r\n\r\n", file_name, ch)
		}
	}
	manifestMf.Close()

	//读取manifest_mf文件再哈希
	manifestByte, err := ioutil.ReadFile(mfName)
	manifestHash := sha1.New()
	manifestHash.Write(manifestByte)


	cf_header := "Signature-Version: 1.0\r\nCreated-By: 1.0 (Android)\r\nSHA1-Digest-Manifest: "+base64.StdEncoding.EncodeToString(manifestHash.Sum(nil))+"\r\n\r\n"
	certSf.Write([]byte(cf_header))
	certSf.Write(certBody.Bytes())
	certSf.Close()

	//读取CERT.SF文件签名
	sfByte, err := ioutil.ReadFile(sfName)

	//签名生成RSA文件
	rsa, err := signPKCS7(rand.Reader, pfxFile, pfxPwd,sfByte)
	if err != nil {
		return fmt.Errorf("apk: %v", err)
	}
	if _, err := certRsa.Write(rsa); err != nil {
		return err
	}
	certRsa.Close()

	if(outApkFile==""){
		outApkFile=putApkFile+"signed.apk"
	}

	//pack
	genApkv1(putApkFile,tmpPath,outApkFile);

	//删除目录
	os.RemoveAll(tmpPath);
	return nil;
}



func genApkv1(outApk string, signDir string,outputFile string)error{
	var offset int64
	// Create a buffer to write our archive to.
	buf := new(bytes.Buffer)
	// Create a new zip archive.
	w := zip.NewWriter(buf)
	// Open a zip archive for reading.
	r, err := zip.OpenReader(outApk)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	// Iterate through the files in the archive,
	for _, f := range r.File {
		//to linux path.
		temName:= filepath.ToSlash(f.Name)
		if(strings.HasPrefix(temName,"META-INF/")){
			continue;
		}
		rc, err := f.Open()
		if(err!=nil){
			continue;
		}
		offset,err=addApk(offset,temName,rc,w);
	}

	//添加签名文件
	signFile := [3] string{"MANIFEST.MF","CERT.SF","CERT.RSA"}
	for _,fname := range signFile {
		f, err := os.Open(signDir+"/"+fname)
		if err != nil {
			return nil
		}
		offset,err=addApk(offset,"META-INF/"+fname,f,w);
	}

	// Make sure to check the error on Close.
	err = w.Close()
	if err != nil {
		return err;
	}

	// Write the aligned zip file
	err = ioutil.WriteFile(outputFile, buf.Bytes(), 0744)
	if err != nil {
		return err;
	}
	return nil;
}

func addApk(offset int64,fName string,rc io.ReadCloser, w *zip.Writer)(int64,error){
	const fileHeaderLen = 30 // + filename + extra
	start := int(offset) + 30 + len(fName)
	extra:=start % 4
	fwhead := &zip.FileHeader{
		Name:   fName,
		Method: zip.Deflate,
		Extra:make([]byte, extra),
	}
	fw, err := w.CreateHeader(fwhead)
	if err != nil {
		return offset,err;
	}
	tempOffSet,_:=io.Copy(fw,rc)
	if err != nil {
		return offset,err;
	}
	rc.Close()
	return offset+tempOffSet,nil;
}


func signPKCS7(rand io.Reader,pfxfile string, password string, msg []byte) ([]byte, error) {

	p12Byte, err := ioutil.ReadFile(pfxfile)
	if err != nil {
		return nil,err;
	}

	priv, cert, err := pkcs12.Decode(p12Byte, password)
	if err != nil {
		return nil,err;
	}

	if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
		return nil,err;
	}


	// Initialize a SignedData struct with content to be signed
	signedData, err := pkcs7.NewSignedData(msg)
	if err != nil {
		return nil,err;
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert, priv, pkcs7.SignerInfoConfig{}); err != nil {
		return nil,err;
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		return nil,err;
	}

	return detachedSignature,nil;
}
