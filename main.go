// XXX? Remove artifacts on removing extension
// XXX? Remove artifacts on force update
// XXX: Remove artifacts on download/prepare/build failures
// XXX: Add upstream website to control
// XXX: Add explenatory LICENSE file
// XXX? Add support for pbuilder
// XXX: Dpkg lint...
// 		> E: chromium-extension-reddit-enhancement-suite source: source-is-missing sources/background.entry.js line length is 536 characters (>512)
// 		> E: chromium-extension-reddit-enhancement-suite source: source-is-missing sources/main.entry.js line length is 797 characters (>512)
// 		> W: chromium-extension-reddit-enhancement-suite: extra-license-file usr/share/chromium/extensions/reddit-enhancement-suite/LICENSE
// 		> W: chromium-extension-https-everywhere: script-not-executable usr/share/chromium/extensions/https-everywhere/chrome-resources/update-from-chrome-svn.sh
// 		> W: chromium-extension-editthiscookie: extended-description-line-too-long
// 		> W: chromium-extension-editthiscookie: extra-license-file usr/share/chromium/extensions/editthiscookie/License.txt
// 		> W: chromium-extension-editthiscookie: duplicate-font-file usr/share/chromium/extensions/editthiscookie/css/font-awesome-4.6.3/fonts/FontAwesome.otf also in fonts-font-awesome
// 		> W: chromium-extension-editthiscookie: duplicate-font-file usr/share/chromium/extensions/editthiscookie/css/font-awesome-4.6.3/fonts/fontawesome-webfont.ttf also in fonts-font-awesome
// 		> W: chromium-extension-editthiscookie: embedded-javascript-library usr/share/chromium/extensions/editthiscookie/lib/tablesorter/jquery.tablesorter.min.js please use libjs-jquery-tablesorter
// 		> E: chromium-extension-editthiscookie: privacy-breach-donation usr/share/chromium/extensions/editthiscookie/options_pages/support.html (https://www.paypalobjects.com/i/btn/btn_donate_sm.gif)
// 		> W: chromium-extension-umatrix: extra-license-file usr/share/chromium/extensions/umatrix/css/fonts/Roboto_Condensed/LICENSE.txt
// 		> W: chromium-extension-umatrix: duplicate-font-file usr/share/chromium/extensions/umatrix/css/fonts/Roboto_Condensed/RobotoCondensed-Bold.ttf also in fonts-roboto-unhinted
// 		> W: chromium-extension-umatrix: duplicate-font-file usr/share/chromium/extensions/umatrix/css/fonts/Roboto_Condensed/RobotoCondensed-BoldItalic.ttf also in fonts-roboto-unhinted

package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/urfave/cli"
)

type Version struct {
	Version  string `json:"version"`
	Major    int64  `json:"-"`
	Minor    int64  `json:"-"`
	Revision int64  `json:"-"`
	Tag      int64  `json:"-"`
}

func (v *Version) String() string {
	return v.Version
}

type Extension struct {
	Name            string  `json:"name"`
	UID             string  `json:"uid"`
	Version         Version `json:"version,omitempty"`
	NewVersion      Version `json:"-"`
	Hash            string  `json:"hash,omitempty"`
	Description     string  `json:"description,omitempty"`
	UpdateAvailable bool    `json:"-"`
	PublicKey       string  `json:"pubkey_hash"`
}

type List struct {
	Extensions []Extension `json:"extensions"`
}

type Template struct {
	Name      string
	PathName  string
	Author    string
	Email     string
	URL       string
	DescShort string
	DescLong  string
	Version   string
	Date      string
}

const (
	SHARE_DIR    string = "/usr/share/chromium-extension-packager"
	WORK_DIR     string = "/var/lib/chromium-extension-packager"
	LIST_FILE    string = "extensions.json"
	DEB_TEMPLATE string = "deb-template"
	DOWNLOAD_DIR string = "archive"
	DEB_RESULTS  string = "builds"
	URL_DOWNLOAD string = "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=$CHROMIUM_VERSION$&x=id%3D$UID$%26uc"
	URL_INFO     string = "https://chrome.google.com/webstore/detail/$UID$"
	PKG_AUTHOR   string = "Subgraph Automated Packager"
	PKG_EMAIL    string = "user@localhost.local"
	DATE_FORMAT  string = "Mon, 02 Jan 2006 15:04:05 +0000"
)

var nameRegexp = regexp.MustCompile(`itemprop="name" content="([^"]+)"`).FindStringSubmatch
var versionRegexp = regexp.MustCompile(`itemprop="version" content="(([0-9]+.?)+[0-9]?)"`).FindStringSubmatch
var descriptionRegexp = regexp.MustCompile(`itemprop="description">(.+)</div>`).FindStringSubmatch
var uidRegexp = regexp.MustCompile(`^[a-zA-Z0-9]{32}$`).MatchString

var extensions []Extension
var chromiumVersion string

func init() {
	if _, err := os.Stat(WORK_DIR); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Unable to find work directory: %s\n"+WORK_DIR)
		os.Exit(1)
	}

	_, err := getChromiumVersion()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to get chromium version: %+v\n", err)
		os.Exit(1)
	}

	es, err := loadExtensionList()
	if err != nil && os.IsNotExist(err) {
		es = &List{Extensions: []Extension{}}
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to load extensions %+v\n", err)
		os.Exit(1)
	}

	extensions = es.Extensions
}

func main() {
	app := cli.NewApp()
	app.Name = "chromium-extension-packager"
	app.Usage = "Chromium Extension Packager"
	app.Author = "Subgraph"
	app.Email = "info@subgraph.com"
	app.Version = "0.0.1"
	app.EnableBashCompletion = true
	app.Commands = []cli.Command{
		{
			Name:   "list",
			Usage:  "[uuid] print extensions information",
			Action: listExtensions,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name: "fetch",
				},
				cli.StringFlag{
					Name:  "uid",
					Value: "",
				},
			},
		},
		{
			Name:   "add",
			Usage:  "<uuid> add an extension to the list",
			Action: addExtension,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "fetch",
					Usage: "Immediately fetch extension information",
				},
				cli.StringFlag{
					Name:  "uid",
					Usage: "Extension UID.",
					Value: "",
				},
			},
		},
		{
			Name:   "remove",
			Usage:  "<uuid> remove an extension from the list",
			Action: removeExtension,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "uid",
					Usage: "Extension UID.",
					Value: "",
				},
			},
		},
		{
			Name:   "update",
			Usage:  "[uuid] update extension(s) package(s)",
			Action: updateExtensions,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "uid",
					Usage: "A specific extension UID to update",
					Value: "",
				},
				cli.StringFlag{
					Name:  "singing-key",
					Usage: "Specify a signing key for the packages",
					Value: "",
				},
				cli.BoolFlag{
					Name:  "verbose",
					Usage: "Show verbose information about the build process",
				},
				cli.BoolFlag{
					Name:  "force",
					Usage: "Force a build even if no updates are available",
				},
				cli.BoolFlag{
					Name:  "batch",
					Usage: "Use batch mode (disable prompting for possible overrides)",
				},
			},
		},
	}
	app.Run(os.Args)
}

func fetchExtensionsInfo(uid string) {
	for ii, _ := range extensions {
		if uid != "" && extensions[ii].UID != uid {
			continue
		}
		err := extensions[ii].fetchExtensionInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to fetch extension info: %+v\n", err)
			os.Exit(1)
		}
	}
}

func listExtensions(c *cli.Context) {
	fuid := c.String("uid")
	fetch := c.Bool("fetch")
	if fuid != "" && !uidRegexp(fuid) {
		fmt.Fprintln(os.Stderr, "Not a valid UID")
		os.Exit(1)
	}

	puid := os.Args[len(os.Args)-1]
	if fuid == "" && uidRegexp(puid) {
		fuid = puid
	}

	if fetch {
		fetchExtensionsInfo(fuid)
	}
	for ii, ee := range extensions {
		if fuid != "" {
			if fuid != ee.UID {
				continue
			}
		}
		n := ee.Name
		if n == "" {
			n = "[unknown]"
		}
		v := ee.Version.String()
		if v == "" {
			v = "x.x.x"
		}
		nv := ee.NewVersion.String()
		if nv != "" && ee.UpdateAvailable == true {
			v = v + " => " + nv
		}
		uid := ee.UID
		ua := "false"
		if ee.UpdateAvailable {
			ua = "true"
		}
		if v == "x.x.x" {
			ua = "[unknown]"
		}
		if ii > 0 && fuid == "" {
			for i := 0; i < 48; i++ {
				fmt.Print("-")
			}
			fmt.Println("")
		}
		fmt.Printf("Name:\t\t%s\n", n)
		fmt.Printf("UID:\t\t%s\n", uid)
		fmt.Printf("Version:\t%s\n", v)
		if fetch {
			fmt.Printf("Updatable:\t%s\n", ua)
		}
		//fmt.Printf("%+v\n", ee)
	}
}

func addExtension(c *cli.Context) {
	fetch := c.Bool("fetch")
	uid := c.String("uid")
	if uid != "" && !uidRegexp(uid) {
		fmt.Fprintln(os.Stderr, "Not a valid UID")
		os.Exit(1)
	}
	puid := os.Args[len(os.Args)-1]
	if uid == "" && uidRegexp(puid) {
		uid = puid
	} else {
		fmt.Fprintln(os.Stderr, "Not a valid UID")
		os.Exit(1)
	}

	for ii, _ := range extensions {
		if extensions[ii].UID == uid {
			fmt.Println("Extension already exists, not adding.")
			os.Exit(0)
		}
	}

	extensions = append(extensions, Extension{UID: uid})
	if fetch {
		for ii, _ := range extensions {
			if extensions[ii].UID == uid {
				extensions[ii].fetchExtensionInfo()
				break
			}
		}
	}

	err := saveExtensionList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func askConfirm(msg string) bool {
	var s string
	fmt.Printf(msg + ": ")
	_, err := fmt.Scanln(&s)
	if err != nil && err.Error() == "unexpected newline" {
		s = "no"
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	return (s == "y" || s == "yes")
}

func removeExtension(c *cli.Context) {
	uid := c.String("uid")
	if uid != "" && !uidRegexp(uid) {
		fmt.Fprintln(os.Stderr, "Not a valid UID")
		os.Exit(1)
	}
	puid := os.Args[len(os.Args)-1]
	if uid == "" && uidRegexp(puid) {
		uid = puid
	} else {
		fmt.Fprintln(os.Stderr, "Not a valid UID")
		os.Exit(1)
	}

	found := false
	var ee Extension
	for ii, _ := range extensions {
		if extensions[ii].UID == uid {
			ee = extensions[ii]
			var title string
			if ee.Name != "" {
				title = ee.Name
			} else {
				title = ee.UID
			}
			if !askConfirm(fmt.Sprintf("Do you really want to remove %s [y/N]: ", title)) {
				fmt.Println("Canceled!")
				os.Exit(0)
			}
			extensions = append(extensions[:ii], extensions[ii+1:]...)
			found = true
			break
		}
	}

	if !found {
		fmt.Println("Extension not found, nothing to remove.")
		os.Exit(0)
	} else {
		fmt.Printf("Removed extension: %+v\n", ee)
	}

	err := saveExtensionList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func updateExtensions(c *cli.Context) {
	verbose := c.Bool("verbose")
	sk := c.String("singing-key")
	batch := c.Bool("batch")
	force := c.Bool("force")
	uid := c.String("uid")
	if uid != "" && !uidRegexp(uid) {
		fmt.Fprintln(os.Stderr, "Not a valid UID")
		os.Exit(1)
	}
	puid := os.Args[len(os.Args)-1]
	if uid == "" && uidRegexp(puid) {
		uid = puid
	}

	if sk != "" && batch {
		fmt.Fprintf(os.Stderr, "WARNING: Running in batch mode with singing key!")
	}

	fetchExtensionsInfo(uid)

	found := false
	for ii, _ := range extensions {
		if uid != "" && extensions[ii].UID != uid {
			continue
		}
		if extensions[ii].UpdateAvailable || force {
			found = true
			if extensions[ii].Version.String() != "" && !force {
				fmt.Printf("Updating %s (%s) from %s to %s...\n",
					extensions[ii].Name,
					extensions[ii].UID,
					extensions[ii].Version.String(),
					extensions[ii].NewVersion.String())
			} else {
				fmt.Printf("Building %s (%s) version %s...\n",
					extensions[ii].Name,
					extensions[ii].UID,
					extensions[ii].NewVersion.String())
			}
			extensions[ii].Version.Version = extensions[ii].NewVersion.String()
			extensions[ii].Version.parse()
			err := extensions[ii].downloadExtensionPack()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to download extension: %+v\n", err)
				os.Exit(1)
			}

			err = extensions[ii].prepareExtensionPackage(batch)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to prepare extension package: %+v\n", err)
				os.Exit(1)
			}

			err = extensions[ii].buildExtensionPackage(verbose, sk)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Unable to build extension package: %+v\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Successfully built extension package for %s (%s) version %s.\n",
					extensions[ii].Name,
					extensions[ii].UID,
					extensions[ii].Version.String())
			}
		}
	}

	if !found {
		fmt.Println("No extension require updating.")
	} else {
		err := saveExtensionList()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}
}

func newList() *List {
	return &List{}
}

func loadExtensionList() (*List, error) {
	cpath := path.Join(WORK_DIR, LIST_FILE)
	bs, err := ioutil.ReadFile(cpath)
	if err != nil {
		return nil, err
	}
	le := newList()
	if err := json.Unmarshal(bs, le); err != nil {
		return nil, err
	}

	for ii, _ := range le.Extensions {
		le.Extensions[ii].Version.parse()
	}

	return le, nil
}

func saveExtensionList() error {
	cpath := path.Join(WORK_DIR, LIST_FILE)
	json, err := json.Marshal(&List{Extensions: extensions})

	if err != nil {
		return fmt.Errorf("Error: could not generate extension list:", err, "\n")
	}

	err = ioutil.WriteFile(cpath, json, 0644)

	if err != nil {
		return fmt.Errorf("Error: could not save extension list:", err, "\n")
	}

	return nil
}

func (e *Version) parse() {
	v := strings.Split(e.String(), ".")
	for i, vv := range v {
		vi, err := strconv.ParseInt(vv, 10, 64)
		if err != nil {
			vi = -1
		}
		switch i {
		case 0:
			e.Major = vi
		case 1:
			e.Minor = vi
		case 2:
			e.Revision = vi
		}
	}
	e.Tag = ((e.Major * 100) + (e.Minor * 10) + e.Revision)
}

func getChromiumVersion() (string, error) {
	if chromiumVersion != "" {
		return chromiumVersion, nil
	}

	ver, err := exec.Command("/usr/lib/chromium/chromium", "--version").Output()
	if err != nil {
		return "", err
	}
	v := strings.Split(strings.Trim(string(ver), "\n "), " ")
	chromiumVersion = v[len(v)-1]
	return chromiumVersion, nil

}

func (e *Extension) fetchExtensionInfo() error {
	url := strings.Replace(URL_INFO, "$UID$", e.UID, -1)
	response, err := http.Get(url)
	if err != nil {
		return err
	} else {
		defer response.Body.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)

		nn := nameRegexp(buf.String())
		if len(nn) < 2 {
			return errors.New("Unable to find match for extension name")
		}
		e.Name = nn[1]

		v := versionRegexp(buf.String())
		if len(v) < 2 {
			return errors.New("Unable to find match for extension version")
		}
		if e.Description == "" {
			d := descriptionRegexp(buf.String())
			if len(v) < 2 {
				fmt.Println("Could not parse extension description")
			} else {
				e.Description = strings.Replace(html.UnescapeString(d[1]), "\n", " ", -1)
			}
		}
		oldv := e.Version.String()
		oldt := e.Version.Tag
		e.NewVersion = Version{Version: v[1]}
		e.NewVersion.parse()
		//fmt.Printf("A: %b (%s), B: %b C: %d %d\n", (oldv == ""), oldv, (oldt < e.NewVersion.Tag), oldt, e.NewVersion.Tag)
		if oldv == "" || oldt < e.NewVersion.Tag {
			e.UpdateAvailable = true
		}
	}

	return nil
}

func (e *Extension) downloadExtensionPack() error {
	fname := strings.Join([]string{e.UID, e.Version.String()}, "-") + ".crx"
	dpath := path.Join(WORK_DIR, DOWNLOAD_DIR)
	cpath := filepath.Clean(path.Join(dpath, fname))
	_, err := os.Stat(cpath)
	if err == nil {
		fmt.Println("Extension pack already exists, skipping download.")
		return nil
	} else {
		fmt.Println("Downloading extension pack from webstore...")
	}
	_, err = os.Stat(dpath)
	if err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(dpath, 0755); err != nil {
			return fmt.Errorf("could not create build path '%s': %v", dpath, err)
		}
	} else if err != nil {
		return nil
	}
	v, err := getChromiumVersion()
	if err != nil {
		return err
	}
	url := strings.Replace(URL_DOWNLOAD, "$CHROMIUM_VERSION$", v, -1)
	url = strings.Replace(url, "$UID$", e.UID, -1)
	out, err := os.Create(cpath)
	if err != nil {
		return err
	}
	defer out.Close()
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

/*
func getExtensionBuildPath() string {
	bp := path.Join(WORK_DIR, DEB_RESULTS)
	_, err := os.Stat(bp)
	if err != nil && !os.IsNotExist(err) {
		if err := os.MkdirAll(bp, 0755); err != nil {
			return fmt.Errorf("could not create build path '%s': %v", bp, err)
		}
	} else if err != nil {
		return nil
	}

	pname := strings.ToLower(strings.Replace(e.Name, " ", "-", -1))
	bname := strings.Join([]string{pname, e.Version.String()}, "-")
}
*/
func (e *Extension) prepareExtensionPackage(batchMode bool) (err error) {
	bp := path.Join(WORK_DIR, DEB_RESULTS)
	_, err = os.Stat(bp)
	if err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(bp, 0755); err != nil {
			return fmt.Errorf("could not create build path '%s': %v", bp, err)
		}
	} else if err != nil {
		return err
	}

	pname := strings.ToLower(strings.Replace(e.Name, " ", "-", -1))
	bname := strings.Join([]string{pname, e.Version.String()}, "-")
	longDesc := ""
	if len(e.Description) < 81 {
		longDesc = " " + e.Description
	} else {
		words := strings.Split(e.Description, " ")
		line := ""
		for i, w := range words {
			line = line + " " + w
			if len(line+" "+w) > 70 || i == len(words)-1 {
				longDesc = longDesc + line + "\n"
				line = ""
			}
		}
	}

	fmt.Printf("Building package template to: %s\n", path.Join(bp, bname))
	err = CopyDir(path.Join(SHARE_DIR, DEB_TEMPLATE), path.Join(bp, bname, "debian"), &Template{
		Name:      e.Name,
		PathName:  pname,
		Author:    PKG_AUTHOR,
		Email:     PKG_EMAIL,
		URL:       strings.Replace(URL_INFO, "$UID$", e.UID, -1),
		DescShort: "Chromium Extension " + e.Name + " (Automatically Packaged)",
		DescLong:  longDesc,
		Version:   e.Version.String(),
		Date:      time.Now().UTC().Format(DATE_FORMAT),
	})

	if err != nil {
		return err
	}

	pl := path.Join(bp, bname, "debian", "loader", "template")
	pn := filepath.Clean(path.Join(bp, bname, "debian", "loader", pname))
	err = os.Rename(pl, pn)
	if err != nil {
		return fmt.Errorf("Could not move loder template: %+v", err)
	}

	sp := path.Join(bp, bname, "sources")
	if err := os.MkdirAll(sp, 0755); err != nil {
		return fmt.Errorf("could not create build path '%s': %v", sp, err)
	}

	fname := strings.Join([]string{e.UID, e.Version.String()}, "-") + ".crx"
	cpath := path.Join(WORK_DIR, DOWNLOAD_DIR, fname)

	data, err := ioutil.ReadFile(cpath)
	if err != nil {
		return err
	}
	ld := int64(len(data))
	data, pk, sign, err := crxToZip(data)
	if err != nil {
		return err
	}
	if len(pk) == 0 || len(sign) == 0 {
		return errors.New("Invalid public key/signature pair for extension")
	}
	hash := sha1.Sum(data)
	re, err := x509.ParsePKIXPublicKey(pk)
	if err != nil {
		return fmt.Errorf("Error parsing public key for %s: %v\n", e.Name, err)
	}
	pkhash := sha256.Sum256(pk)
	if e.PublicKey == "" {
		e.PublicKey = fmt.Sprintf("%x", pkhash)
	} else if e.PublicKey != fmt.Sprintf("%x", pkhash) {
		if batchMode || !askConfirm("WARNING: Public Key Changed! Continue anyway [y/N]") {
			return errors.New("Canceled due to public key change!")
		}
	}
	rk := re.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(rk, crypto.SHA1, hash[:], sign)
	if err != nil {
		return fmt.Errorf("Error verifying signature for %s: %v\n", e.Name, err)
	}
	buf := bytes.NewReader(data)
	r, err := zip.NewReader(buf, ld)
	if err != nil {
		return err
	}

	for _, f := range r.File {
		dst := filepath.Clean(path.Join(sp, f.Name))
		if f.Mode()&os.ModeSymlink != 0 {
			continue
		}

		if f.FileInfo().IsDir() {
			err = os.MkdirAll(dst, 0755) //f.Mode().Perm())
			if err != nil {
				return err
			}
			continue
		}

		dirdst := path.Dir(dst)
		_, err = os.Stat(dirdst)
		if err != nil && os.IsNotExist(err) {
			err = os.MkdirAll(dirdst, 0755) //f.Mode().Perm())
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer func() {
			if e := out.Close(); e != nil {
				err = e
			}
		}()
		_, err = io.Copy(out, rc)
		if err != nil {
			return err
		}
		err = out.Sync()
		if err != nil {
			return err
		}
		if err := rc.Close(); err != nil {
			return err
		}
		err = os.Chmod(dst, 0644) //f.Mode().Perm())
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Extension) buildExtensionPackage(verbose bool, singingKey string) error {
	bp := path.Join(WORK_DIR, DEB_RESULTS)
	pname := strings.ToLower(strings.Replace(e.Name, " ", "-", -1))
	bname := strings.Join([]string{pname, e.Version.String()}, "-")
	sp := path.Join(bp, bname)

	arg := "--no-sign"
	if singingKey != "" {
		arg = "--sign-key=" + singingKey
	}
	cmd := exec.Command("dpkg-buildpackage", arg)
	cmd.Dir = sp
	cmd.Env = append(os.Environ())

	if verbose {
		cmd.Env = append(cmd.Env, "DPKG_COLORS=always")
		pe, err := cmd.StderrPipe()
		if err != nil {
			return fmt.Errorf("error creating stderr pipe for build process: %v", err)
		}

		po, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("error creating stdout pipe for build process: %v", err)
		}

		go printBuildOut(pe, os.Stderr)
		go printBuildOut(po, os.Stdout)
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		ss := 0
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				ss = status.ExitStatus()
			}
		}
		return fmt.Errorf("Failed to build extension package with exit %d (%+v)", ss, err)
	}

	return nil
}

func printBuildOut(pp io.ReadCloser, out *os.File) {
	io.Copy(out, pp)
	pp.Close()
}

// CopyFile copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file. The file mode will be copied from the source and
// the copied data is synced/flushed to stable storage.
func CopyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if e := out.Close(); e != nil {
			err = e
		}
	}()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	err = out.Sync()
	if err != nil {
		return err
	}

	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		return err
	}

	return err
}

func ApplyTemplate(src, dst string, tmpl *Template) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		if e := out.Close(); e != nil {
			err = e
		}
	}()

	buf := new(bytes.Buffer)
	buf.ReadFrom(in)

	t := template.Must(template.New("file").Parse(buf.String()))
	err = t.Execute(out, tmpl)
	if err != nil {
		return err
	}

	err = out.Sync()
	if err != nil {
		return
	}

	si, err := os.Stat(src)
	if err != nil {
		return
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		return
	}

	return nil
}

// CopyDir recursively copies a directory tree, attempting to preserve permissions.
// Source directory must exist, destination directory must *not* exist.
// Symlinks are ignored and skipped.
func CopyDir(src, dst string, tmpl *Template) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !si.IsDir() {
		return fmt.Errorf("source is not a directory")
	}

	_, err = os.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		return fmt.Errorf("destination already exists")
	}

	err = os.MkdirAll(dst, si.Mode())
	if err != nil {
		return err
	}

	entries, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Clean(filepath.Join(src, entry.Name()))
		dstPath := filepath.Clean(filepath.Join(dst, entry.Name()))

		if entry.IsDir() {
			err = CopyDir(srcPath, dstPath, tmpl)
			if err != nil {
				return err
			}
		} else {
			// Skip symlinks.
			if entry.Mode()&os.ModeSymlink != 0 {
				continue
			}

			if strings.HasSuffix(srcPath, ".in") {
				dstPath = strings.TrimSuffix(dstPath, ".in")
				err = ApplyTemplate(srcPath, dstPath, tmpl)
				if err != nil {
					return err
				}
			} else {
				err = CopyFile(srcPath, dstPath)
				if err != nil {
					return err
				}
			}
		}
	}

	return err
}

func crxCalcLength(a, b, c, d byte) uint64 {
	length := uint64(0)
	length = length + uint64(a)
	length = length + (uint64(b) << 8)
	length = length + (uint64(c) << 16)
	length = length + (uint64(d) << 24)
	return length
}

// https://developer.chrome.com/apps/crx
// https://github.com/peerigon/unzip-crz
func crxToZip(buf []byte) ([]byte, []byte, []byte, error) {
	// Already a zip file
	if buf[0] == 80 && buf[1] == 75 && buf[2] == 3 && buf[3] == 4 {
		return buf, nil, nil, nil
	}

	if buf[0] != 67 || buf[1] != 114 || buf[2] != 50 || buf[3] != 52 {
		return buf, nil, nil, errors.New("Invalid CRX header: Does not start with Cr24")
	}

	if buf[4] != 2 || buf[5] != 0 || buf[6] != 0 || buf[7] != 0 {
		return buf, nil, nil, errors.New("Unexpected CRX format version")
	}

	pubKeyLength := crxCalcLength(buf[8], buf[9], buf[10], buf[11])
	signatureLength := crxCalcLength(buf[12], buf[13], buf[14], buf[15])

	signatureOffset := 16 + pubKeyLength
	zipOffset := signatureOffset + signatureLength

	return buf[zipOffset:len(buf)], buf[16:signatureOffset], buf[signatureOffset:(signatureOffset + signatureLength)], nil
}
