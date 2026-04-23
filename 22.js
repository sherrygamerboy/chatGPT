import React from "react";

function UserDescription({ userDescription }) {
    return (
        <div
            // React requires this for HTML rendering
            // Make sure content is sanitized before using this in production
            dangerouslySetInnerHTML={{
                __html: userDescription || ""
            }}
        />
    );
}

export default UserDescription;