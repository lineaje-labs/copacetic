package output

import (
	"os"

	"github.com/project-copacetic/copacetic/pkg/output/lineaje"
	"github.com/project-copacetic/copacetic/pkg/types"
)

func Save(err error, result *types.PatchResult, format string, output string, startTime string) {
	if format != "lineaje" || len(output) == 0 {
		return
	}
	_, statErr := os.Stat(output)
	if statErr == nil { // Do not overwrite the existing output file
		return
	}
	newLineajeOutput := lineaje.NewLineajeOutput(err, result, startTime)
	_ = newLineajeOutput.Save(output)
}
