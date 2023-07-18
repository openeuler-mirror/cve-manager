package obs

type OBS interface {
	Upload(fileName string, data []byte) error
}
