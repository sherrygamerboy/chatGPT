import React from "react";
import DOMPurify from "dompurify";

const UserContent = ({ htmlContent }) => {
    // Sanitize user-provided HTML to prevent XSS (CWE-79)
    const sanitizedContent = DOMPurify.sanitize(htmlContent || "", {
        USE_PROFILES: { html: true }
    });

    return (
        <div
            dangerouslySetInnerHTML={{
                __html: sanitizedContent
            }}
        />
    );
};

export default UserContent;