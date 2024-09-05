# API Testing Checklist

## 1. Testing Approach <br />
- **Determine Testing Approach**: Choose between black box &emsp;|&emsp; gray box &emsp;|&emsp; or white box testing based on the level of access and information available.<br />

## 2. Passive Reconnaissance <br />
- **Attack Surface Discovery**: Identify all potential entry points and attack vectors.<br />
  - ***Tools:*** &emsp;|&emsp; [Shodan](#) &emsp;|&emsp; [Censys](#) &emsp;|&emsp; [Google Dorking](#) &emsp;|&emsp; [Recon-ng](#) &emsp;|&emsp; [BuiltWith](#)<br />
- **Exposed Secrets**: Check for sensitive information such as API keys &emsp;|&emsp; tokens &emsp;|&emsp; and credentials that might be inadvertently exposed.<br />
  - ***Tools:*** &emsp;|&emsp; [GitHub Search](#) &emsp;|&emsp; [GitLab Search](#) &emsp;|&emsp; [TruffleHog](#) &emsp;|&emsp; [LeakCanary](#) &emsp;|&emsp; [DataLeaker](#)<br />

## 3. Active Reconnaissance <br />
- **Port and Service Scanning**: Use tools to scan for open ports and services that may reveal additional endpoints or vulnerabilities.<br />
  - ***Tools:*** &emsp;|&emsp; [Nmap](#) &emsp;|&emsp; [Masscan](#) &emsp;|&emsp; [ZMap](#) &emsp;|&emsp; [Angry IP Scanner](#) &emsp;|&emsp; [Netcat](#)<br />
- **Application Usage**: Interact with the application as an end-user to understand its behavior and API usage patterns.<br />
  - ***Tools:*** &emsp;|&emsp; [Browser DevTools](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Insomnia](#)<br />
- **Inspect with DevTools**: Utilize browser developer tools to analyze network requests &emsp;|&emsp; responses &emsp;|&emsp; and JavaScript files.<br />
  - ***Tools:*** &emsp;|&emsp; [Chrome DevTools](#) &emsp;|&emsp; [Firefox Developer Tools](#) &emsp;|&emsp; [Edge DevTools](#) &emsp;|&emsp; [Fiddler](#) &emsp;|&emsp; [Burp Suite](#)<br />
- **API Directory Discovery**: Search for directories related to the API &emsp;|&emsp; such as `/api/` &emsp;|&emsp; `/v1/` &emsp;|&emsp; or `/endpoints/`.<br />
  - ***Tools:*** &emsp;|&emsp; [DirBuster](#) &emsp;|&emsp; [Dirsearch](#) &emsp;|&emsp; [Gobuster](#) &emsp;|&emsp; [Wfuzz](#) &emsp;|&emsp; [Burp Suite](#)<br />
- **Endpoint Discovery**: Identify all available API endpoints using tools.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [API Discovery Tools](#) &emsp;|&emsp; [API Fortress](#)<br />

## 4. Endpoint Analysis <br />
- **API Documentation Review**: Locate and examine official API documentation or any available resources that describe the API’s functionality.<br />
  - ***Tools:*** &emsp;|&emsp; [Swagger UI](#) &emsp;|&emsp; [Redoc](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [API Blueprint](#) &emsp;|&emsp; [OpenAPI Specification](#)<br />
- **Reverse Engineering**: Analyze the API's underlying structure to understand its implementation.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [Fiddler](#) &emsp;|&emsp; [Charles Proxy](#)<br />
- **Use the API as Intended**: Interact with the API based on its documented functionality to identify potential issues.<br />
  - ***Tools:*** &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [Insomnia](#) &emsp;|&emsp; [cURL](#) &emsp;|&emsp; [HTTPie](#) &emsp;|&emsp; [SoapUI](#)<br />
- **Analyze Responses**: Look for information disclosures &emsp;|&emsp; excessive data exposures &emsp;|&emsp; and business logic flaws.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [Fiddler](#) &emsp;|&emsp; [Wireshark](#)<br />

## 5. Authentication Testing <br />
- **Basic Authentication Testing**: Test for flaws in basic authentication mechanisms.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [Nessus](#) &emsp;|&emsp; [Hydra](#)<br />
- **API Token Manipulation**: Attempt to exploit and manipulate API tokens.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [JWT.io Debugger](#) &emsp;|&emsp; [Auth0](#) &emsp;|&emsp; [Burp Suite Extensions](#)<br />

## 6. Fuzzing <br />
- **Fuzz All Inputs**: Use fuzzing techniques to test API inputs for unexpected behavior or vulnerabilities.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [AFL](#) &emsp;|&emsp; [Peach Fuzzer](#) &emsp;|&emsp; [Boofuzz](#)<br />

## 7. Authorization Testing <br />
- **Resource Identification Methods**: Discover how resources are identified and accessed.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [API Testing Tools](#) &emsp;|&emsp; [Access Control Tester](#)<br />
- **Broken Object Level Authorization (BOLA)**: Test for flaws in object-level access control.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [API Security Testing Tools](#) &emsp;|&emsp; [Manual Testing](#)<br />
- **Broken Function Level Authorization (BFLA)**: Test for flaws in function-level access control.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [API Security Testing Tools](#) &emsp;|&emsp; [Manual Testing](#)<br />

## 8. Mass Assignment Testing <br />
- **Discover Standard Parameters**: Identify parameters used in requests that might be susceptible to mass assignment attacks.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [API Testing Tools](#) &emsp;|&emsp; [Manual Testing](#)<br />
- **Test for Mass Assignment**: Check if the API allows users to modify parameters that should be restricted.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [API Security Testing Tools](#) &emsp;|&emsp; [Manual Testing](#)<br />

## 9. Injection Testing <br />
- **User Input Testing**: Discover and test requests that accept user input for injection vulnerabilities.<br />
  - ***Tools:*** &emsp;|&emsp; [SQLmap](#) &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Commix](#) &emsp;|&emsp; [Fuzzing Tools](#)<br />
- **Test for XSS/XAS**: Test for Cross-Site Scripting (XSS) and XML Injection vulnerabilities.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [XSSer](#) &emsp;|&emsp; [XSStrike](#) &emsp;|&emsp; [XML Injector](#)<br />
- **Database-Specific Attacks**: Perform attacks tailored to specific database systems.<br />
  - ***Tools:*** &emsp;|&emsp; [SQLmap](#) &emsp;|&emsp; [MySQLi](#) &emsp;|&emsp; [NoSQLMap](#) &emsp;|&emsp; [PostgreSQL Tools](#) &emsp;|&emsp; [SQLNinja](#)<br />
- **Operating System Injection**: Test for operating system command injection vulnerabilities.<br />
  - ***Tools:*** &emsp;|&emsp; [Commix](#) &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Metasploit](#) &emsp;|&emsp; [Netcat](#)<br />

## 10. Rate Limit Testing <br />
- **Check for Rate Limits**: Test if the API enforces rate limits to prevent abuse.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [Rate Limit Tester](#) &emsp;|&emsp; [Wfuzz](#)<br />
- **Test Rate Limit Bypass Methods**: Explore ways to bypass or evade rate limits.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Postman](#) &emsp;|&emsp; [Rate Limit Bypass Tools](#) &emsp;|&emsp; [Manual Testing](#)<br />

## 11. Evasive Techniques <br />
- **String Terminators**: Add string terminators to payloads to test for evasion.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Fuzzing Tools](#) &emsp;|&emsp; [Custom Scripts](#) &emsp;|&emsp; [Manual Testing](#)<br />
- **Case Switching**: Modify the case of payloads to bypass filters.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Fuzzing Tools](#) &emsp;|&emsp; [Custom Scripts](#) &emsp;|&emsp; [Manual Testing](#)<br />
- **Payload Encoding**: Encode payloads to avoid detection.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Fuzzing Tools](#) &emsp;|&emsp; [Custom Scripts](#) &emsp;|&emsp; [Manual Testing](#)<br />
- **Combine Evasion Techniques**: Use a combination of evasive techniques to increase effectiveness.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Fuzzing Tools](#) &emsp;|&emsp; [Custom Scripts](#) &emsp;|&emsp; [Manual Testing](#)<br />
- **Apply Evasion to All Tests**: Ensure that evasive techniques are applied to all previous tests.<br />
  - ***Tools:*** &emsp;|&emsp; [Burp Suite](#) &emsp;|&emsp; [OWASP ZAP](#) &emsp;|&emsp; [Fuzzing Tools](#) &emsp;|&emsp; [Custom Scripts](#) &emsp;|&emsp; [Manual Testing](#)<br />

