# Generate Possible Passwords

* Use company's name, seasons, months, all appended with years
* Eg: Shinra2023, Fall2020, october2023

<pre class="language-bash"><code class="lang-bash">wget https://raw.githubusercontent.com/n000b3r/Generate-Possible-Passwords/refs/heads/main/generate_possible_passwords.py
<strong>
</strong><strong># Append years to wordlist
</strong><strong>python generate_possible_passwords.py -f possible_words.txt
</strong><strong>
</strong><strong># Generate seasons + year
</strong>python generate_possible_passwords.py --seasons

# Generate months + year
python generate_possible_passwords.py --months
</code></pre>
