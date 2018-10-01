package fs

import (
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// DisplayFile is fed to the template table
type DisplayFile struct {
	Name, URL, Modified string
	Size                int64
	IsDir               bool
}

// Display is fed to the template
type Display struct {
	Dir, Parent string
	Contents    []DisplayFile
}

// TODO switch to https://bitters.bourbon.io/ or something: bootstrap is stupid heavy weight for this.
var fileList = template.Must(template.New("fileList").Parse(`
<!doctype html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Directory Contents {{ .Dir }}</title>
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
  <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.3.1/css/all.css" integrity="sha384-mzrmE5qonljUremFsqc01SB46JvROS7bZs3IO2EmfFsd15uHvIt+Y8vEf7N7fWAU" crossorigin="anonymous">
</head>

<body>
  <div id="container">
    <div class="row">
      <div class="col-1"></div>
      <div class="col-8">
        <h1>Directory Contents {{ .Dir }}</h1>
      </div>
      <div class="col-3"/></div>
    </div>
    <div class="row">
      <div class="col-1"></div>
      <div class="col-8">
        <table class="table-sm">
          <thead>
            <tr>
              <th scope="col">Type</th>
              <th scope="col">Filename</th>
              <th scope="col">Size <small>(bytes)</small></th>
              <th scope="col">Date Modified</th>
            </tr>
          </thead>
          <tbody>
            {{- if ne .Dir "/" -}}
            <tr>
              <td><i class="fas fa-undo-alt"></i></td>
              <td colspan="3"><a href="{{ .Parent }}">Parent Dir</a></td>
            </tr>
            {{- end -}}
            {{- range .Contents -}}
            <tr>
              {{- if .IsDir -}}
              <td><i class="fas fa-folder"></i></td>
              {{- else -}}
              <td><i class="far fa-file"></i></td>
              {{- end -}}
              <td><a href="{{ .URL }}">{{- .Name }}</a></td>
              <td>{{- .Size -}}</td>
              <td>{{- .Modified -}}</td>
            </tr>
            {{ end }}
          </tbody>
      </table>
    </div>
    <div class="col-3"/></div>
  </div>
</html>
`))

// GoodDir implments FileSystem
type GoodDir string

// isSecret is PoC; also should have passwords and config hidden
func isSecret(p string) bool {
	_, file := filepath.Split(p)
	return strings.HasPrefix(file, ".")
}

// mapDirOpenError maps the provided non-nil error from opening name
// to a possibly better non-nil error. In particular, it turns OS-specific errors
// about opening files in non-directories into os.ErrNotExist. See Issue 18984.
// It is stolen from the standard library
// XXX USED
func mapDirOpenError(originalErr error, name string) error {
	if os.IsNotExist(originalErr) || os.IsPermission(originalErr) {
		return originalErr
	}

	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		fi, err := os.Stat(strings.Join(parts[:i+1], string(filepath.Separator)))
		if err != nil {
			return originalErr
		}
		if !fi.IsDir() {
			return os.ErrNotExist
		}
	}
	return originalErr
}

// FilteredFile is a file: but only if it isn't secret. or something
type FilteredFile struct {
	*os.File
}

// Readdir Filters out the dotfiles
func (ff FilteredFile) Readdir(count int) ([]os.FileInfo, error) {
	fi, err := ff.File.Readdir(count)
	if err != nil {
		return nil, err
	}
	ffi := make([]os.FileInfo, 0, len(fi))
	for _, f := range fi {
		if strings.HasPrefix(f.Name(), ".") {
			continue
		}
		ffi = append(ffi, f)
	}
	return ffi, nil
}

// Open opens; but not dotfiles
func (d GoodDir) Open(name string) (http.File, error) {
	if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) {
		return nil, errors.New("http: invalid character in file path")
	}

	dir := string(d)
	if dir == "" {
		dir = "."
	}

	fullName := filepath.Join(dir, filepath.FromSlash(path.Clean("/"+name)))

	// Hide the secrets
	if isSecret(fullName) {
		return nil, os.ErrNotExist
	}

	f, err := os.Open(fullName)
	if err != nil {
		return nil, mapDirOpenError(err, fullName)
	}
	return FilteredFile{f}, nil
}

// toHTTPError returns a non-specific HTTP error message and status code
// for a given non-nil error value. It's important that toHTTPError does not
// actually return err.Error(), since msg and httpStatus are returned to users,
// and historically Go's ServeContent always returned just "404 Not Found" for
// all errors. We don't want to start leaking information in error messages.
// XXX USED
func toHTTPError(err error) (msg string, httpStatus int) {
	if os.IsNotExist(err) {
		return "404 page not found", http.StatusNotFound
	}
	if os.IsPermission(err) {
		return "403 Forbidden", http.StatusForbidden
	}
	// Default:
	return "500 Internal Server Error", http.StatusInternalServerError
}

// localRedirect gives a Moved Permanently response.
// It does not convert relative paths to absolute paths like Redirect does.
// XXX USED
func localRedirect(w http.ResponseWriter, r *http.Request, newPath string) {
	if q := r.URL.RawQuery; q != "" {
		newPath += "?" + q
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(http.StatusMovedPermanently)
}

// ServeFile with new layouts
func ServeFile(w http.ResponseWriter, r *http.Request, fs http.FileSystem, name string, redirect bool) {
	const indexPage = "/index.html"

	// Guards and Redirect only
	f, err := fs.Open(name)
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}
	defer f.Close()

	d, err := f.Stat()
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}

	if d.IsDir() {
		url := r.URL.Path
		if url[len(url)-1] != '/' {
			localRedirect(w, r, path.Base(url)+"/")
			return
		}
		dirList(w, r, f)
		return
	}
	var path string
	switch t := fs.(type) {
	case GoodDir:
		path = string(t)
	default:
		panic(1)
	}
	// just send the file
	http.ServeFile(w, r, path)
	return
}

// dirList a templated version of the built in; with no '.' files
func dirList(w http.ResponseWriter, r *http.Request, f http.File) {
	dirs, err := f.Readdir(-1)
	if err != nil {
		log.Printf("http: error reading directory: %v", err)
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}
	currentDir := r.URL.Path
	parentDir := filepath.Dir(filepath.Clean(currentDir))

	// no sleep: probably easier way of doing this
	sort.Slice(dirs, func(i, j int) bool {
		if dirs[i].IsDir() && dirs[j].IsDir() {
			return dirs[i].Name() < dirs[j].Name()
		} else if dirs[i].IsDir() && !dirs[j].IsDir() {
			return true
		} else if !dirs[i].IsDir() && dirs[j].IsDir() {
			return false
		}
		return dirs[i].Name() < dirs[j].Name()
	})

	list := make([]DisplayFile, 0, len(dirs))

	for _, d := range dirs {
		if err != nil {
			log.Printf("http: error reading file: %v", err)
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}

		modTime, _ := d.ModTime().MarshalText()
		name := d.Name()
		url := url.URL{Path: name}
		if d.IsDir() {
			name += "/"
		}
		list = append(list, DisplayFile{
			Name:     template.HTMLEscapeString(name),
			URL:      url.String(),
			Modified: string(modTime),
			Size:     d.Size(),
			IsDir:    d.IsDir(),
		})
		// name may contain '?' or '#', which must be escaped to remain
		// part of the URL path, and not indicate the start of a query
		// string or fragment.
	}

	d := Display{
		Dir:      currentDir,
		Parent:   parentDir,
		Contents: list,
	}

	fileList.ExecuteTemplate(w, "fileList", d)
}

type fileHandler struct {
	root http.FileSystem
}

// ServeHTTP with custom ServeFile
func (f *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	ServeFile(w, r, f.root, path.Clean(upath), true)
}

func FileServer(root http.FileSystem) http.Handler {
	return &fileHandler{root}
}
