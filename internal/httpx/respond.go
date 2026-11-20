package httpx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/bootdotdev/learn-web-security/internal/templates"
	"github.com/bootdotdev/learn-web-security/internal/textutils"
)

const safeServerErrorMessage = "The request failed. Try again, or return to the store."

// RespondWithError writes a JSON error response, logging server-error diagnostics
// while withholding them from the client.
func RespondWithError(responseWriter http.ResponseWriter, code int, message string) {
	message = textutils.StripANSI(message)
	if code >= http.StatusInternalServerError {
		fmt.Printf("Responding with error code %v, message: %v\n", code, message)
		message = safeServerErrorMessage
	}
	RespondWithJSON(responseWriter, code, map[string]string{"error": message})
}

func RespondWithJSON(responseWriter http.ResponseWriter, code int, payload any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(code)
	encoder := json.NewEncoder(responseWriter)
	if err := encoder.Encode(payload); err != nil {
		log.Printf("Error respondWithJSON: status code %v: %v", code, err)
	}
}

// RespondWithErrorPage renders an error page, withholding server-error details
// from the client, and returns any rendering error.
func RespondWithErrorPage(responseWriter http.ResponseWriter, renderer *templates.Renderer, statusCode int, title, message string) error {
	if statusCode >= http.StatusInternalServerError {
		title = "Something Went Wrong"
		message = safeServerErrorMessage
	}
	return renderer.Render(responseWriter, statusCode, "error", templates.ErrorPage{
		Page:       templates.Page{Title: title},
		StatusCode: statusCode,
		Message:    message,
	})
}
