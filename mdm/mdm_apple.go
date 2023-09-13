package mdm

func NewAppleMDMHandler(settings *MDMSettings) *MDMHandler {
	return &MDMHandler{Settings: settings}
}
