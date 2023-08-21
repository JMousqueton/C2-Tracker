
curl https://codeload.github.com/montysecurity/C2-Tracker/zip/refs/heads/main -o /tmp/tmp.zip
unzip -j -o  /tmp/tmp.zip 'C2-Tracker-main/data/*' -d ./data
git add . 
git commit --all --message "Nightly Update"
git push
