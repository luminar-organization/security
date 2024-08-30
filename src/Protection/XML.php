<?php

namespace Luminar\Security\Protection;

use DOMDocument;

class XML
{
    /**
     * @param string $content
     * @return DOMDocument
     */
    public function parse(string $content): DOMDocument
    {
        $xml = new DOMDocument();
        $xml->loadXML($content, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_NOCDATA);
        return $xml;
    }
}