0. Hostname and add it to /etc/hosts

1. Server Information
- nmap -sCV
- curl -s -v 10.10.11.208 

2. Fuzz input
2.1 Using FUFF

  *1 Intercept and send the request to the repeater and right click and select "copy to file"
  ![image](https://github.com/user-attachments/assets/64b68dd4-5c28-441e-9cae-9a8c93338375)
  *2 Add "FUZZ" to the field we want to fuzz
  ![image](https://github.com/user-attachments/assets/f7fc735a-fc9b-4afb-8924-3e9862295f91)
  *3 Run FUFF(-ms 0: match size 0)
  ```bash
  ffuf -request search.req -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt -ms 0
  ```
