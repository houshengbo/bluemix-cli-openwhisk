// Code generated by go-bindata.
// sources:
// wski18n/resources/en_US.all.json
// DO NOT EDIT!

package wski18n

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _wski18nResourcesEn_usAllJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x96\xc1\x6e\x1a\x3d\x10\x80\xef\x79\x8a\x11\x97\x5c\xd0\xfe\x77\x6e\xfc\x6d\x0f\x39\x34\x41\xa5\x55\x0e\x55\xa5\x4c\x76\x07\x76\x84\x19\xaf\xec\x01\x4a\x56\xfb\xee\x95\x97\x6c\x41\x2a\x71\xec\x40\x0e\x11\x87\xf1\x37\x9f\x67\xc7\x63\xff\xbc\x01\x00\x68\xfb\xff\xe1\x6f\xc4\xd5\x68\x02\xa3\x1f\x9e\x1c\x08\xae\x09\x50\xaa\xff\xac\x83\x06\xbd\xdf\x59\x57\xc1\x8e\x1c\x81\x58\x05\xdf\x50\xc9\x0b\xa6\x6a\x34\x3e\xae\x56\x87\xe2\x0d\x2a\x5b\xc9\xc6\xf4\x94\x6e\xfc\x86\x90\xe0\xb3\x21\x50\x0b\x58\x96\xe4\x3d\xfc\x6f\x36\xb4\xe6\xdf\x30\x9d\xdd\x41\x6d\xbd\x4e\xa0\x6d\x0b\x72\xae\xeb\x62\x3e\x19\x94\x8f\xe9\xe0\x46\x6b\xeb\xf8\xa5\x4f\x09\x24\x55\x63\x59\x2e\x94\x7b\x97\x99\xaa\xba\xd1\x9a\x44\xb9\x44\x25\xd8\xb1\xd6\x43\x86\x5c\xbd\x04\x4e\xa2\x92\x23\x75\x4c\x5b\xea\x9b\xc4\x37\x58\x92\xcf\x94\x89\x13\xa2\x1a\xf7\xc3\x0a\xb8\x6d\xdb\x22\xac\xef\xba\x5b\x60\xdf\xf7\x25\x0b\x68\x4d\x60\xd8\x2b\xd8\x05\x84\xfd\xaa\xa1\xea\x24\x4d\x44\xef\x52\x72\x54\x7b\x68\x8b\x4d\x38\x5c\x4f\xf7\xd3\xaf\x5f\x9e\x22\x2a\xe7\xa2\x33\xf0\xb3\xe9\x7c\xfe\xf8\xf0\xed\x73\x7a\x8a\xe3\x8a\x68\x9a\x87\x86\xe4\xb1\x66\xbf\x3a\x48\xcd\x67\xd3\x4f\xd1\x7d\x9c\x8f\x8f\xa6\x78\x7e\xf5\x62\x51\x5a\xba\x03\xe9\xed\x04\xe7\xa2\xa3\x78\x63\x97\xe1\x53\xda\xa1\xfb\x23\xec\x7f\x42\x13\x8f\x87\xc7\x2d\xf5\xcd\x32\x94\xf8\x00\x7a\x9d\x0f\x6a\x57\x24\x99\xc7\x25\x8f\x18\xd5\xbc\x13\x25\x27\x68\x80\x9c\xb3\xae\x80\xe3\x17\x0a\xd3\xb4\x6d\x0b\x6c\xb8\xeb\x42\xd7\xb3\x6c\xd1\x70\x95\xa4\x7a\x09\x35\xb1\xaa\x2c\xac\x8c\x86\x5f\x08\x3c\xb9\x2d\x39\x28\xad\x08\x95\x41\x21\xb3\x9c\x89\xa8\xac\x3a\x9e\xde\x49\xd7\xaa\x62\x3a\x33\xbf\x86\x03\xfb\x8a\xb5\x4c\x41\x46\x45\xe7\x64\xa8\x54\xc0\xe3\x50\x9d\x44\x1c\xce\x45\x47\xf1\xdf\xeb\xf0\x7c\x41\x17\xbc\x2d\xac\x51\xf6\x27\xd3\x3b\xec\xa5\x62\xdf\x18\xdc\x8f\xa1\x31\x84\x9e\x40\xf7\x0d\x0d\x83\xff\x6f\x64\xff\xab\x88\x78\x5d\x35\x4d\x74\x43\x6d\x5b\xd8\x55\xd7\x41\xff\x60\x0b\x77\x56\x98\xe5\xe1\xce\x32\x76\xb9\xa4\x2a\x0c\xc5\x94\x39\x97\x85\x89\x77\xda\x40\x18\x2e\xcf\xf5\xc6\x2b\xd4\x61\x7a\xa1\x42\xd8\xad\x82\x15\x82\x8a\x16\x2c\xa7\x97\xe7\x7b\xaf\xd1\x0f\x31\x0f\xaa\x37\xbf\x6e\xfe\x04\x00\x00\xff\xff\x05\xb1\xc6\x8f\x2f\x0b\x00\x00")

func wski18nResourcesEn_usAllJsonBytes() ([]byte, error) {
	return bindataRead(
		_wski18nResourcesEn_usAllJson,
		"wski18n/resources/en_US.all.json",
	)
}

func wski18nResourcesEn_usAllJson() (*asset, error) {
	bytes, err := wski18nResourcesEn_usAllJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "wski18n/resources/en_US.all.json", size: 2863, mode: os.FileMode(420), modTime: time.Unix(1493735865, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"wski18n/resources/en_US.all.json": wski18nResourcesEn_usAllJson,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"wski18n": &bintree{nil, map[string]*bintree{
		"resources": &bintree{nil, map[string]*bintree{
			"en_US.all.json": &bintree{wski18nResourcesEn_usAllJson, map[string]*bintree{}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

