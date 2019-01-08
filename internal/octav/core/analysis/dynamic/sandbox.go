package dynamic

// https://github.com/digitalocean/go-qemu ?

type SandBoxState int

const (
	ON SandBoxState = iota
	OFF SandBoxState = iota
	DEAD SandBoxState = iota
)

type SandBox struct {
	name         string
	diskFilename string
	state        SandBoxState
}

func (sandbox SandBox) create() {
	// The sandbox and the host have to be as close as possible (same arch, same kernel version, same distribution)
}

func (sandbox SandBox) snapshot() {

}

func (sandbox SandBox) restore() {

}

func (sandbox SandBox) start() {

}

func (sandbox SandBox) remove() {

}