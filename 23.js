const RichText = ({ content }) => (
    <div dangerouslySetInnerHTML={{ __html: content }} />
);

export default RichText;


//-----------------------------------------

<div dangerouslySetInnerHTML={{ __html: content }} />