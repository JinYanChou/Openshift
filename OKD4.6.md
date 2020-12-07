使用此文章的 DNS、HAProxy 可安裝完成 https://medium.com/swlh/guide-okd-4-5-single-node-cluster-832693cb752b

VMWare Fusion
  /Library/Preferences/VMware Fusion/vmnet8/dhcpd.conf
    ip range: 192.168.104.128 ~ 192.168.104.254
    gateway: 192.168.104.2

bastion: 192.168.104.130
master: 192.168.104.131
bootstrap: 192.168.104.132

# Install CentOS 8

# 1.設定IP
sudo nmtui

systemctl restart NetworkManager.service
ifdown enp0s8
ifup enp0s8

# 2.安裝必要軟體
sudo dnf install -y vim podman httpd dnsmasq dnsmasq-utils jq telnet

# 加外部 DNS
sudo vi /etc/dnsmasq.conf
# 新增：server=8.8.8.8

sudo vi /etc/hosts

192.168.104.130 bastion.okd.local
192.168.104.131 master.lab.okd.local
192.168.104.132 bootstrap.lab.okd.local api.lab.okd.local api-int.lab.okd.local
# 192.168.104.132 worker.lab.okd.local console-openshift-console.lab.okd.local oauth-openshift.lab.okd.local

sudo systemctl enable dnsmasq
sudo systemctl start dnsmasq
sudo firewall-cmd --add-service=dns --permanent
sudo firewall-cmd --reload

# 設定 DNS 到自己的服務
sudo nmtui

sudo mkdir -p /opt/registry/{auth,certs,data}

cd /opt/registry/certs
sudo openssl req -newkey rsa:4096 -nodes -sha256 -keyout domain.key -x509 -days 36500 -out domain.crt

sudo htpasswd -bBc /opt/registry/auth/htpasswd admin admin

# 調整擁有者
sudo chown -R admin:admin /opt/registry/

podman run --name mirror-registry -p 5000:5000 \
-v /opt/registry/data:/var/lib/registry:z \
-v /opt/registry/auth:/auth:z \
-e "REGISTRY_AUTH=htpasswd" \
-e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
-e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
-v /opt/registry/certs:/certs:z \
-e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
-e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
-e REGISTRY_COMPATIBILITY_SCHEMA1_ENABLED=true \
-d docker.io/library/registry:2

curl -u admin:admin -k https://bastion.okd.local:5000/v2/_catalog

sudo firewall-cmd --add-port=5000/tcp --zone=internal --permanent
sudo firewall-cmd --add-port=5000/tcp --zone=public --permanent
sudo firewall-cmd --reload

# 加入 Registry 的 Certificate（需使用root）
sudo cp /opt/registry/certs/domain.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust

# download pull-secret.json
https://cloud.redhat.com/openshift/install/pull-secret

# 將下載的 pull-secret 加上 Private Registry 的帳密
podman login --authfile ~/pull-secret.json bastion.okd.local:5000

# 下載 OKD 的 CLI（不要下載到 Openshift 版本）
curl -LO https://github.com/openshift/okd/releases/download/4.6.0-0.okd-2020-11-27-200126/openshift-client-linux-4.6.0-0.okd-2020-11-27-200126.tar.gz

tar xzvf openshift-client-linux.tar.gz
sudo mv kubectl /usr/local/bin
sudo mv oc /usr/local/bin

export OCP_RELEASE=4.6.0-0.okd-2020-11-27-200126
export LOCAL_REGISTRY='bastion.okd.local:5000'
export LOCAL_REPOSITORY='okd4/okd46'
export PRODUCT_REPO='openshift'
export LOCAL_SECRET_JSON='/home/admin/pull-secret.json'
export RELEASE_NAME="okd"

oc adm -a ${LOCAL_SECRET_JSON} release mirror \
--from=quay.io/${PRODUCT_REPO}/${RELEASE_NAME}:${OCP_RELEASE} \
--to=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY} \
--to-release-image=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}

curl -X GET -u admin:admin -k https://bastion.okd.local:5000/v2/okd4/okd46/tags/list | jq .

# COPY

imageContentSources:
- mirrors:
  - bastion.okd.local:5000/okd4/okd46
  source: quay.io/openshift/okd
- mirrors:
  - bastion.okd.local:5000/okd4/okd46
  source: quay.io/openshift/okd-content


oc adm release extract \
-a ${LOCAL_SECRET_JSON} \
--command=openshift-install \
"${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}"


# 產生 install-config.yaml
ssh-keygen -t rsa -b 4096 -N ''

apiVersion: v1
baseDomain: okd.local
metadata:
  name: lab

compute:
- hyperthreading: Enabled
  name: worker
  replicas: 0

controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: 1

networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16

platform:
  none: {}

fips: false
pullSecret: '{"auths": {"bastion.okd.local:5000": {"auth": "YWRtaW46YWRtaW4="}}}'
sshKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLW7bIysdfpPw8tpEAGZNcmp6v0gIDaoTnE/y2TTCv9YRgSh7XfJtDunZM+4VK+auYy6t0quqmgtqNuWPuGz66evdhxgzVlHW9WM7+tKww7wBF2WR17kfUU+TlRDSnc4qWeKN6kx9avXCmFAgJq6DJeRm9QNBNYkysq/2ydUd+X3NjcIOgESDhuRhbVb8LY8xx1xj9uO6Y6nCDU9WCf1SSjeRT1rk3dqKMGMMz90SciZssVKhuSHde8svtf7LOFguitK+2LXJGt96upghmp22hhIlrgchI3hDDp4fMn5EDsNARp+tx0V/EFY+3nBgltD6eNcTEeCySMMQpaIX1bpD7P44vDZWr/aT68wFW4Wwl6lLwW7VC8qoeJq2KbDvNf/7Gw2r+D+wyHwUwzlvdhB6JzKjrLABZ963VsjYJZmdjGQUjXdCWDRvAem000A6WPfiLRevGhBnCMN2N1szjjBg/A8cQlpjmS2SnhtT7qSn0lvpFaYo/pKg0/bLRfYhMCUm1s1Bcyal4ZQpvsumd2IhzVFaWun7JVrJgiD+mzX2/gymbC9YaAATlVzEk/8TMnzaQRxEl8sKT+Pj+R5k+lTylKFVdFZ2gV/KjVzQYKe5GOIRzc0wgRcYJGhP4qAEZz0+aQ+9/h8LX2wiu5wzWcdjCMnLTIv8ZAXR7foiuWft7zQ== admin@bastion.okd.local'
additionalTrustBundle: |
  -----BEGIN CERTIFICATE-----
  MIIF9zCCA9+gAwIBAgIUDldrO/LgWTbyFZ5fKg0OkRXku8cwDQYJKoZIhvcNAQEL
  BQAwgYkxCzAJBgNVBAYTAlRXMQ8wDQYDVQQIDAZUYWl3YW4xDzANBgNVBAcMBlRh
  aXBlaTETMBEGA1UECgwKQ2F0aGF5bGlmZTEaMBgGA1UEAwwRYmFzdGlvbi5va2Qu
  bG9jYWwxJzAlBgkqhkiG9w0BCQEWGGppbnlhbkBjYXRoYXlsaWZlLmNvbS50dzAg
  Fw0yMDExMjkxNDI1NDdaGA8yMTIwMTEwNTE0MjU0N1owgYkxCzAJBgNVBAYTAlRX
  MQ8wDQYDVQQIDAZUYWl3YW4xDzANBgNVBAcMBlRhaXBlaTETMBEGA1UECgwKQ2F0
  aGF5bGlmZTEaMBgGA1UEAwwRYmFzdGlvbi5va2QubG9jYWwxJzAlBgkqhkiG9w0B
  CQEWGGppbnlhbkBjYXRoYXlsaWZlLmNvbS50dzCCAiIwDQYJKoZIhvcNAQEBBQAD
  ggIPADCCAgoCggIBAKg4Kx7ehAolw3kq8v0puZAj9uqo58HVqSgqP6oBNZBQOKBh
  HoBAFXfOl9K0KaBVTFbgjt5lANnnft76R4h7LHWGNSbiCzNEn2HNBshuA5nWDpSD
  YuaQzLPDi6IVNmV5kVJzdkoAQovsIMLt9z0t487kNIgihQig/wREpU6QC1Sdzcl5
  jYnZpWL/4wYADJHwKK3mDrMBTaUqJNMDWVwKB6G8UHIAbKFSRHMI8kCwnqR8Un/A
  eQh99Rpc2wWSm42tFn1dG1UkfrNqvLItLE2BU/j1jHIPbQkcJJrC6XLSXckSl7tA
  HHRQI9mbSL3L6i7BH1rtNjyBSosBl9oLVaSfN414k94hAFhzGFLn5vVsSe5ESSzG
  II45KBK4J40YTP5M79uuYl//5cmY4tOwZ7R7uj0V77J6Xt8hUUgusEnDFksmxkKG
  dHF6633OoSnVh58QamsTE99a7fsqQcQ9UpwvZ8oRR9TJPILMViI7IyJiL6uePYTm
  Ser5/z9a8i66iXJ0cqPJ9MAuswthZRhDHw+6dR0k8zB8VsRIhNFVX0hZiqYFtiKv
  SkBai4lw8+qdTi7Np/lY4RUjAZsVc6YFvysLK2qvJMg6wd5Bau/uo+2Jr3hOpmgJ
  eicFvwPUZ46fNR3X4iim3wlDiQdBAv3ibg32AyeGsQvbjoz36ekf/tJP7Xi3AgMB
  AAGjUzBRMB0GA1UdDgQWBBS3lWNXu8G9+u31vDHXXSm+Rgj7ljAfBgNVHSMEGDAW
  gBS3lWNXu8G9+u31vDHXXSm+Rgj7ljAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
  DQEBCwUAA4ICAQCQ94mPiKoG+wtBcPlccLkRLlbIVjr/zHzTPv+ITDYOEEShvBzB
  LWCcLtEOblKegqLJPPRW0IGsBDR1BWK3v14npO+pLLhvEr968e4E8pqccQQ01sMk
  w9KY4xZ6ispeEbI4axV6KO1JAQxxOYSU5QKzlSjU7uQ0F0cXNFxUoydZxkCrhXbo
  eUr2JhagERgGk7cim6cHXdok4pD994oty1+uaesz0tu2rn3gB28tl+cRRg25uERG
  RQe7ecm5KK1kEc5rDMHwOz7VFWFJ9fChCc8iIaGgUYgN00BCObCs8mo/zqO7neMH
  /0FhqlVW5DGZkvKnH2LvvoJuez4VuokMmFVXKCpbE2vT8MfJ6Fx1BqtxeYbUCpRE
  DsvN6rGvUIb9MlgRFh11LuoLqonxzkLVQ9B1HljBQsAHWbjimmiH584ikLBscdUU
  /BDZQ+0CHBKitOxDLK92PAd/kLx2PUQwMCqoiB+W0GkK+LxhFexCp//gD/bldsHt
  syHMzfRYkf9HM4FHwtVmrE6Zdl5r1opKs3yhMuG0tesewCMnhlr1gBugPutvkag1
  Dh4fCUGAhOYcHJaT+sOE/Ytzk26JZmEG1E5EPnL55RRiP85g7y0EWDf8TjaEyERX
  cFQRf6RmJEaPQ4z5YUHdSF2MGw1rnlRdLkGo/kqIvpyiDPhlwJjNlCXPfw==
  -----END CERTIFICATE-----
imageContentSources:
- mirrors:
  - bastion.okd.local:5000/okd4/okd46
  source: quay.io/openshift/okd
- mirrors:
  - bastion.okd.local:5000/okd4/okd46
  source: quay.io/openshift/okd-content


openshift-install create manifests --dir=install_dir/

# 調整成 Control-Plane-Node 不能佈署
vi install_dir/manifests/cluster-scheduler-02-config.yml

openshift-install create ignition-configs --dir=install_dir/


sudo systemctl status httpd

sudo mkdir /var/www/html/okd4
sudo cp -R install_dir/* /var/www/html/okd4/
sudo chown -R apache: /var/www/html/
sudo chmod -R 755 /var/www/html/

sudo setsebool -P httpd_read_user_content 1
sudo systemctl enable httpd
sudo systemctl start httpd
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --reload

curl http://bastion.okd.local/okd4/metadata.json

---

VirtualBox 安裝 coreos 時要選 Linux / Other Linux (64 Bit)

sudo nmtui

curl -LO http://bastion.lab.okd.local/okd4/bootstrap.ign
coreos-installer install /dev/sda --firstboot-args=console=foo -n -i bootstrap.ign

# 安裝完成，重啟伺服器 sudo reboot

coreos.inst.install_dev=/dev/sda 
coreos.inst.ignition_url=http://192.168.104.130/okd4/bootstrap.ign
ip=192.168.104.132::192.168.104.2:255.255.255.0:bookstrap.lab.okd.local:ens33:none
nameserver=192.168.104.130

---

# Bootstrap Node
# 可透過 Bastion Server SSH 到 Bootstrap
ssh core@bootstrap.lab.okd.local

journalctl -b -f -u kubelet.service
journalctl -b -f -u bootkube.service

# 安裝過程式重啟，重啟後才可使用 crictl 指令
sudo crictl pods

# 如果有很多服務，則可繼續安裝 control-plane-node

# 在 Bastion Server 執行以下指令等待安裝完成

openshift-install --dir=install_dir wait-for bootstrap-complete --log-level=debug

# 抓 coreos 的 log
openshift-install gather bootstrap --dir=./install_dir --bootstrap=bootstrap.lab.okd.local --master=master.lab.okd.local
openshift-install gather bootstrap --dir=./install_dir --bootstrap=okd4-bootstrap.lab.okd.local --master=okd4-control-plane-1.lab.okd.local

