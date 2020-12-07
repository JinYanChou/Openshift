使用此文章的 DNS、HAProxy 可安裝完成 https://medium.com/swlh/guide-okd-4-5-single-node-cluster-832693cb752b

VMWare Fusion
  /Library/Preferences/VMware Fusion/vmnet8/dhcpd.conf
    ip range: 192.168.104.128 ~ 192.168.104.254
    gateway: 192.168.104.2

bastion: 192.168.104.130
master: 192.168.104.131
bootstrap: 192.168.104.132

VirtualBox
  File / Host Network Manager...

  sudo vim /etc/NetworkManager/NetworkManager.conf

  # And add this to the [main] section:
  dns=none

  systemctl restart NetworkManager

bastion: 192.168.1.210
master: 192.168.1.201
bootstrap: 192.168.1.202

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

192.168.1.210 bastion.okd.local
192.168.1.201 master.lab.okd.local
192.168.1.202 bootstrap.lab.okd.local api.lab.okd.local api-int.lab.okd.local
# 192.168.1.202 worker.lab.okd.local console-openshift-console.lab.okd.local oauth-openshift.lab.okd.local

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
curl -LO https://github.com/openshift/okd/releases/download/4.5.0-0.okd-2020-10-15-235428/openshift-client-linux-4.5.0-0.okd-2020-10-15-235428.tar.gz

tar xzvf openshift-client-linux-4.5.0-0.okd-2020-10-15-235428.tar.gz
sudo mv kubectl /usr/local/bin
sudo mv oc /usr/local/bin

# 設定環境變數
# https://quay.io/repository/openshift-release-dev/ocp-release?tab=tags

export OCP_RELEASE=4.5.0-0.okd-2020-10-15-235428
export LOCAL_REGISTRY='bastion.okd.local:5000'
export LOCAL_REPOSITORY='okd4/okd45'
export PRODUCT_REPO='openshift'
export LOCAL_SECRET_JSON='/home/admin/pull-secret.json'
export RELEASE_NAME="okd"

# 將伺服器的 image 同步到本地端
oc adm -a ${LOCAL_SECRET_JSON} release mirror \
--from=quay.io/${PRODUCT_REPO}/${RELEASE_NAME}:${OCP_RELEASE} \
--to=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY} \
--to-release-image=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}

# 確認 image 已同步
curl -X GET -u admin:admin -k https://bastion.okd.local:5000/v2/okd4/okd45/tags/list | jq .

# COPY for install-config.yaml

imageContentSources:
- mirrors:
  - bastion.okd.local:5000/okd4/okd45
  source: quay.io/openshift/okd
- mirrors:
  - bastion.okd.local:5000/okd4/okd45
  source: quay.io/openshift/okd-content

# 產生 openshift-install 執行檔，並複製到 /usr/local/bin
oc adm release extract \
-a ${LOCAL_SECRET_JSON} \
--command=openshift-install \
"${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}"

sudo mv openshift-install /usr/local/bin

# 產生 ssh key for install-config.yaml
ssh-keygen -t rsa -b 4096 -N ''

# 產生 install-config.yaml
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
sshKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC4uMlJewUB2zHsV0eiHcoH8+cZu25eDSxoVo4QhnoQouzNIdgrGJplfF9JRsTHrwK8uKx6RScYqrrLhlGVImxat19OJpjeCB0xOf/uMIs8urrhhDo+JbfhouZ5fPVoPykWtfWtRia6yZq3QoyOH3OYL92H+f/LU/uB5vLEiPw77iWRQoLo3rYf4QLUoXDTVupViY3+n763tGw9yDNlkKTssIRPvpdODO73aPh9MGRHwNCRIsGU/r0twjNgP2SP1nYRbI+AeU1Z39N9uDrnEi51eFWhTB9qPU0/3QFnclEEZfbEKchJK/EJUeMEUgAf84LbrGcFMqt6EOO56dpn/pSO6YCs71nVQ4GeC8k4bBuxE7DAtpKaHjds8ix+FBi5F78tF8twQKWaYhKrsYGipsnzIOPmOJjD96xC70rjn52g8A/SsYsoRUscs2lA4Ti1zO5f47TjyKTu55dRPXFUhStDw5nEVlbpsOl/QoBBN/IFaRBERKLuwjdwH7WZ6BTSAyeKr6F7FT8uEyA+NqJ4a1HchAtUrIM3E5FF0TXmUiWduPu+BkXk+w8PCAEH4+ugAfydX4pUxQVjeFTiC5R6VDYZ6SloeHwZyPxe5LbdENSP31d9nRP83SDQQkvze2CK6U3hUzFbXjdLvJnrEpPjSLcQp5rnjoNcc7CQPopHGak6Sw== admin@bastion.okd.local'
additionalTrustBundle: |
  -----BEGIN CERTIFICATE-----
  MIIF9zCCA9+gAwIBAgIUbCyUCccryi1A5iCCaffrT7XcxG8wDQYJKoZIhvcNAQEL
  BQAwgYkxCzAJBgNVBAYTAlRXMQ8wDQYDVQQIDAZUYWl3YW4xDzANBgNVBAcMBlRh
  aXBlaTETMBEGA1UECgwKQ2F0aGF5bGlmZTEaMBgGA1UEAwwRYmFzdGlvbi5va2Qu
  bG9jYWwxJzAlBgkqhkiG9w0BCQEWGGppbnlhbkBjYXRoYXlsaWZlLmNvbS50dzAg
  Fw0yMDExMzAwMzE5MzhaGA8yMTIwMTEwNjAzMTkzOFowgYkxCzAJBgNVBAYTAlRX
  MQ8wDQYDVQQIDAZUYWl3YW4xDzANBgNVBAcMBlRhaXBlaTETMBEGA1UECgwKQ2F0
  aGF5bGlmZTEaMBgGA1UEAwwRYmFzdGlvbi5va2QubG9jYWwxJzAlBgkqhkiG9w0B
  CQEWGGppbnlhbkBjYXRoYXlsaWZlLmNvbS50dzCCAiIwDQYJKoZIhvcNAQEBBQAD
  ggIPADCCAgoCggIBALnMtYrrLTrP7Ntta/ObeAx0F3jM0s00PKBAW1vZhNZH5zdz
  pVG+Bk8/1pU8J/yBDf5D6xpgW+UXTyrXPKk4jqvr75rIbVqyjFPan/1edT9uVIlg
  25/A6g6JhuFD81hJy7XJ6T4s1ATAo0HK6Ub3MpooCVE5/Os2PQFjTygvLOHYG+Ei
  zEaPdQSoTvlEPwVqCKExAihmboxpNqzWUERtGi2JNS5SCA4MOhejVZ3lp3b+KagL
  s573Q1HJ2LeZcM/NVF6Lr7qtUJ3DDJZ/Isy8x9tfYgTX/VklL9zAY9I2B+RzGcip
  VNlwt0Gibq+GNEf3DLdit7A7UZvP8STqIoQ/++J1zN/Q7iNu5ibt90jjJ10LYJB2
  uG7FlaW3jvQaHfYcGcGV3YDWpnBigSjWTuHLQUbKR+zSEixsDY9NXWC5DG8RK643
  cwx2JDY+svsjlsJgTNii6eD7GylUQ+n5oe3qkQLNo/71oG83yML/P/aivH6PS9sR
  GmS6ZPKv8teTCWisxR1qp9hGFJEcMayQTg7Js5S+EGx6wlD+PwpqvWAv3kejj4+n
  Y4PljvrW2/u7x//7LTGX2JaJE7G/jS8Gy4Dn6lup5SXVJw+vjgMtcNopAMwmBYCw
  MOO1MA1NtmVv+CQ+oMtMuyyhcH6AfZKm7RVwT5WAtCCCe/pP5Hlr7/2HHJJ9AgMB
  AAGjUzBRMB0GA1UdDgQWBBT9mkjMiMw6tKQfX3RzoHa2lOjmDjAfBgNVHSMEGDAW
  gBT9mkjMiMw6tKQfX3RzoHa2lOjmDjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
  DQEBCwUAA4ICAQBtbBlRb9miJjP6wU5GFnKoB2ziyIzMC4T3lXwV2hSHDLoICdSp
  OadJ1rPU8VnCacAHACZ6mV+r8/Gj3/LB282xWJQxTveR6LucPSnAq51j0/Iu5fSZ
  MnK+uLEjiETxvIgFNXgIE4cxjUSjRSPM7P6Djti6/d/mGGXQ74QrSFrDKUYHIWbJ
  9s4RzlPAGEGYn67XuyPhWXsz17x5T12XvjeZwqHO+YiygtARuI6IbVUY0wTbj/3r
  b9lYIM84czRa6+4Yxw+Y1hHizGTf4Si6XKkeHgeJl/xGzzlLWvo3SvsVaqCwHOZL
  s7RBULOV3mTwV2+uNHnHwAIjlIXhqImEGcF+bsQY/wzSEFLgOt5c0enasV7Y2rCj
  d8YWg0qmmH3Kk/5AD3C9slg/S5F3xdbVjXQ8PunCYy7zRrrihyu4OQBMhVBBf7Vi
  VzAfRx3NwOZ9Fftsctz3pT7dbBdBd3FEYLqOAxQdUvpGqGirS/EbSFNLmtbBoxkT
  r9wxRYdZoHPjT4AGa5PXfFVfwdB/mfVuYhSlH0Avjqrd/KVBmi0W4pHtTA17+vmD
  9PKg+0DWsPc89EWlC5Q8yxFWbP+pRpq0W3sObDS8MO/NBrxA/9xFEwWnpBEkcxDY
  cFxWUS+iAuBxAy3maUTBCneGJX8kqY7VJ8NGDiIVznZL73hjncqML7jzpw==
  -----END CERTIFICATE-----
imageContentSources:
- mirrors:
  - bastion.okd.local:5000/okd4/okd45
  source: quay.io/openshift/okd
- mirrors:
  - bastion.okd.local:5000/okd4/okd45
  source: quay.io/openshift/okd-content

# 產生 yaml 檔
openshift-install create manifests --dir=install_dir/

# 調整成 Control-Plane-Node 不能佈署
vi install_dir/manifests/cluster-scheduler-02-config.yml

# 產生 ignition
openshift-install create ignition-configs --dir=install_dir/

# 建立 http 伺服器
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

sudo systemctl status httpd

curl http://bastion.okd.local/okd4/metadata.json

---

VirtualBox 安裝 coreos 時要選 Linux / Other Linux (64 Bit)

# 安裝方法一：
# 調整網路設定

sudo nmtui

# 安裝 Bootstrap
curl -LO http://bastion.okd.local/okd4/bootstrap.ign
coreos-installer install /dev/sda --firstboot-args=console=foo -n -i bootstrap.ign

# 安裝完成，重啟伺服器 sudo reboot

# 安裝方法二：
coreos.inst.install_dev=/dev/sda 
coreos.inst.ignition_url=http://192.168.104.130/okd4/bootstrap.ign
ip=192.168.104.132::192.168.104.2:255.255.255.0:bookstrap.lab.okd.local:ens33:none
nameserver=192.168.104.130

---

# 安裝 Master Node
coreos.inst.install_dev=/dev/sda 
coreos.inst.ignition_url=http://192.168.104.130/okd4/master.ign
ip=192.168.104.131::192.168.104.2:255.255.255.0:master.lab.okd.local:ens33:none
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

---

除錯指令

openssl s_client -connect api-int.lab.okd.local:22623 | openssl x509 -noout -text
ssh core@okd4-bootstrap.lab.okd.local chronyc tracking
ssh core@okd4-bootstrap.lab.okd.local curl https://api-int.lab.okd.local:22623/config/master
ssh admin@192.168.60.240 netstat -nltupe | grep -E ':80|:443|:6443|:22623'
ssh admin@192.168.60.240 ss -nltupe | grep -E ':80|:443|:6443|:22623'
ssh core@okd4-bootstrap.lab.okd.local curl https://api-int.lab.okd.local:22623/config/worker
curl -sk https://api-int.lab.okd.local:22623/config/master

oc --kubeconfig=./kubeconfig adm must-gather --image=bastion.lab.okd.local:5000/okd4/okd45@sha256:ae9949b075844ccaeb149dd0a33ad380976762e5cdeb4735d99063c2a2178401
oc --kubeconfig=./kubeconfig get events -n openshift-must-gather-scpm5

---

OpenShift 版本
https://openshift-release.svc.ci.openshift.org/

現有版本 Life Cycle Dates
https://access.redhat.com/support/policy/updates/openshift/

OCP 現有版本的描述 4.y.z （例如4.6.1）
y 版本通常一季一次，且會寫在 roadmap 中
每一個 y 版本都會對應一個新的 K8S 版本
Ex: 4.6 是 K8S 1.19
    4.5 是 K8S 1.18
z 版本通常一週發佈一次

參考文件：https://my.oschina.net/u/4567873/blog/4697460

OKD 版本
https://origin-release.apps.ci.l2s4.p1.openshiftapps.com/
https://github.com/openshift/okd/releases

---

問題一：
各節點的日期時間要一致？bastion可能時區會不一樣，不確定有沒有影響

問題二：
master node 一直連不到 22623 port connection refused
後來改用以下方式安裝，就可以了？

coreos.inst.install_dev=/dev/sda 
coreos.inst.ignition_url=http://192.168.60.240:8080/okd4/maaster.ign
ip=192.168.60.241::192.168.60.254:255.255.255.0:okd4-control-plane-1.lab.okd.local:enp0s3:none
nameserver=192.168.60.240

問題三：
不知道是不是一定要用 Load Balance 才能安裝

問題四：
要注意不要抓到 Openshift 的版本，無法安裝在 Fedora Core OS

---

升級

  973  oc get clusterloggings.logging.openshift.io
  974  oc get clusteroperators.config.openshift.io -A
  975  oc get cvo
  976  oc get clusterversions.config.openshift.io
  977  oc edit clusterversions.config.openshift.io version
  978  oc edit clusterversions.config.openshift.io version
  979  oc get clusteroperator authentication -o yaml
  980  oc create secret tls custom-wildcard-new1      --cert=wildcard.crt      --key=wildcard.key      -n openshift-config
  981  oc create configmap custom-wildcard-new1      --from-file=ca-bundle.crt=wildcard.crt      -n openshift-config
  982  oc patch proxy/cluster      --type=merge      --patch='{"spec":{"trustedCA":{"name":"custom-wildcard-new1"}}}'
  983  oc create secret tls custom-wildcard-new1      --cert=wildcard.crt      --key=wildcard.key      -n openshift-ingress
  984  oc patch ingresscontroller.operator default      --type=merge -p      '{"spec":{"defaultCertificate": {"name": "custom-wildcard-new1"}}}'      -n openshift-ingress-operator
  985  watch oc get node
  986  oc get machineconfigpool
  987  oc adm release info
  988  podman login cxlokdbnt01.okdpaas.cathaylife.com.tw:5000
  989  oc adm upgrade --helo
  990  oc adm upgrade --help
  991  oc adm upgrade --allow-explicit-upgrade --to-image ${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}@sha256:67cc7cb47d56237adcf0ecc2ee76446785add5fa236cd08746b55f578b9200a5 --force=true
  992  LOCAL_REGISTRY='cxlokdbnt01.okdpaas.cathaylife.com.tw:5000'
  993  LOCAL_REPOSITORY='okd4/okd46'
  994  oc adm upgrade --allow-explicit-upgrade --to-image ${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}@sha256:67cc7cb47d56237adcf0ecc2ee76446785add5fa236cd08746b55f578b9200a5 --force=true
  995  oc adm upgrade --allow-explicit-upgrade --to-image ${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}@sha256:67cc7cb47d56237adcf0ecc2ee76446785add5fa236cd08746b55f578b9200a5 --force=true --allow-upgrade-with-warnings
  996  oc get clusterversion
  997  watch oc get clusterversion
  998  oc adm upgrade --help
  999  oc get pod
 1000  oc logs oauth-openshift-5c94b8f546-qfv6g

---

錯誤訊息：
error pinging docker registry 127.0.0.1:5000: Get https://127.0.0.1:5000/v2/: x509: certificate is valid for 192.168.1.210, not 127.0.0.1

解決方法：
vi /etc/containers/registries.conf
# 新增以下內容
[[registry]]
prefix = '192.168.1.210:5000'
insecure = true
location = "192.168.1.210:5000"

---

錯誤訊息：
error authenticating creds for "192.168.1.210:5000": error creating new docker client: error loading registries: mixing sysregistry v1/v2 is not supported

解決方法：
vi /etc/containers/registries.conf

# 刪除 v1 的格式
# 範例 v1
[registries.search]
registries = ['registry.access.redhat.com', 'registry.fedoraproject.org', 'registry.centos.org', 'docker.io']

[registries.insecure]
registries = ['192.168.24.1:8787', 'localhost:8787', 'standalone.ctlplane.localdomain:8787']

[registries.block]
registries = []

# 範例 v2
[[registry]]
prefix = "docker.io"
insecure = true
location = "docker.io"
[[registry.mirror]]
location = "192.168.0.127:5000"
insecure = true

[[registry]]
prefix = '192.168.24.1:8787'
insecure = true
location = '192.168.24.1:8787'

[[registry]]
prefix = 'localhost:8787'
insecure = true
location = 'localhost:8787'

[[registry]]
prefix = 'standalone.ctlplane.localdomain:8787'
insecure = true
location = 'standalone.ctlplane.localdomain:8787'


[[registry]]
prefix = '10.95.28.159:8083'
insecure = true
location = '10.95.28.159:8083'
