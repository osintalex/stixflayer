# STIX 2.1 Meta Objects Test Suite - LanguageContent
import json
import pytest

from stixflayer import LanguageContent


class TestLanguageContentCreation:
    """Test basic LanguageContent creation."""

    def test_create_with_object_ref(self):
        """Test creating LanguageContent with required object_ref."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Test"})
        json_str = lc.to_json()
        data = json.loads(json_str)
        assert data["object_ref"] == "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"

    def test_type_property(self):
        """Test type property returns language-content."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        assert lc.type == "language-content"


class TestInsertContentStrings:
    """Test insert_content_strings method."""

    def test_insert_single_language_string_content(self):
        """Test inserting string content for a single language."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Evil Corp"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert "contents" in data
        assert "en" in data["contents"]
        assert data["contents"]["en"]["name"] == "Evil Corp"

    def test_insert_multiple_language_string_content(self):
        """Test inserting string content for multiple languages."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Threat Actor", "description": "A threat actor"})
        lc.insert_content_strings("de", {"name": "Böse Org", "description": "Die Bedrohungsakteursgruppe"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert "en" in data["contents"]
        assert "de" in data["contents"]
        assert data["contents"]["en"]["name"] == "Threat Actor"
        assert data["contents"]["de"]["name"] == "Böse Org"

    def test_insert_content_with_unicode(self):
        """Test inserting content with unicode characters."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("de", {"name": "Böse Örg", "description": "Über uns: €100"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["contents"]["de"]["name"] == "Böse Örg"
        assert data["contents"]["de"]["description"] == "Über uns: €100"

    def test_insert_content_with_special_chars(self):
        """Test inserting content with special characters."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings(
            "en",
            {"name": "Test 'quoted'", "description": "Line 1\nLine 2\tTab"},
        )
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["contents"]["en"]["name"] == "Test 'quoted'"
        assert "Line 1\nLine 2\tTab" in data["contents"]["en"]["description"]


class TestInsertContentLists:
    """Test insert_content_lists method."""

    def test_insert_list_content_single_language(self):
        """Test inserting list content for a single language."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_lists("en", {"goals": ["Goal 1", "Goal 2"]})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert "contents" in data
        assert "en" in data["contents"]
        assert data["contents"]["en"]["goals"] == ["Goal 1", "Goal 2"]

    def test_insert_list_content_multiple_languages(self):
        """Test inserting list content for multiple languages."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_lists("en", {"aliases": ["Alpha", "Beta"]})
        lc.insert_content_lists("fr", {"aliases": ["Alpha", "Beta"]})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["contents"]["en"]["aliases"] == ["Alpha", "Beta"]
        assert data["contents"]["fr"]["aliases"] == ["Alpha", "Beta"]

    def test_insert_list_with_empty_string_for_missing(self):
        """Test STIX spec: empty string for missing translations."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_lists("fr", {"goals": ["Voler de l'argent en banque", ""]})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["contents"]["fr"]["goals"] == ["Voler de l'argent en banque", ""]


class TestCombinedMethods:
    """Test combining multiple insert methods."""

    def test_string_and_list_different_languages(self):
        """Test combining strings and lists for different languages."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Evil Corp"})
        lc.insert_content_lists("de", {"goals": ["Goal 1", "Goal 2"]})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["contents"]["en"]["name"] == "Evil Corp"
        assert data["contents"]["de"]["goals"] == ["Goal 1", "Goal 2"]

    def test_multiple_language_codes(self):
        """Test multiple RFC 5646 language codes."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Threat Actor"})
        lc.insert_content_strings("de", {"name": "Böse Org"})
        lc.insert_content_strings("fr", {"name": "Organisation maléfique"})
        lc.insert_content_strings("es", {"name": "Organización maléfica"})
        lc.insert_content_strings("ja", {"name": "脅威アクター"})
        lc.insert_content_strings("zh", {"name": "威胁参与者"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert "en" in data["contents"]
        assert "de" in data["contents"]
        assert "fr" in data["contents"]
        assert "es" in data["contents"]
        assert "ja" in data["contents"]
        assert "zh" in data["contents"]


class TestStixCompliance:
    """Test STIX 2.1 compliance."""

    def test_required_fields_present(self):
        """Test all required fields are present in output."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Test"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["type"] == "language-content"
        assert data["spec_version"] == "2.1"
        assert "id" in data
        assert data["id"].startswith("language-content--")
        assert "created" in data
        assert "modified" in data
        assert data["object_ref"] == "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        assert "contents" in data

    def test_roundtrip_serialization(self):
        """Test serialization produces valid JSON that can be parsed by standard json module."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Evil Corp", "description": "A threat actor"})
        lc.insert_content_strings("de", {"name": "Böse Org", "description": "Die Bedrohungsakteursgruppe"})

        json_str = lc.to_json()
        parsed = json.loads(json_str)

        assert parsed["contents"]["en"]["name"] == "Evil Corp"
        assert parsed["contents"]["de"]["name"] == "Böse Org"
        assert json.dumps(parsed) is not None

    def test_valid_json_output(self):
        """Test produces valid JSON that can be serialized."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Test"})
        json_str = lc.to_json()

        parsed = json.loads(json_str)
        assert isinstance(json.dumps(parsed), str)


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_string_value(self):
        """Test empty string as value."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "", "description": "Empty name"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["contents"]["en"]["name"] == ""
        assert data["contents"]["en"]["description"] == "Empty name"

    def test_list_with_values(self):
        """Test list with actual values."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_lists("en", {"goals": ["Goal 1", "Goal 2", "Goal 3"]})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["contents"]["en"]["goals"] == ["Goal 1", "Goal 2", "Goal 3"]

    def test_multiple_properties_separate_languages(self):
        """Test multiple properties across different languages."""
        lc = LanguageContent("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings(
            "en",
            {
                "name": "Evil Corp",
                "description": "Threat actor",
            },
        )
        lc.insert_content_lists("de", {"goals": ["Goal 1", "Goal 2"]})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["contents"]["en"]["name"] == "Evil Corp"
        assert data["contents"]["en"]["description"] == "Threat actor"
        assert data["contents"]["de"]["goals"] == ["Goal 1", "Goal 2"]


class TestComplexObjectRef:
    """Test with various object_ref types."""

    def test_indicator_ref(self):
        """Test with indicator object_ref."""
        lc = LanguageContent("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["object_ref"] == "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        assert data["contents"]["en"]["pattern"] == "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"

    def test_identity_ref(self):
        """Test with identity object_ref."""
        lc = LanguageContent("identity--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "ACME Corp"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["object_ref"] == "identity--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        assert data["contents"]["en"]["name"] == "ACME Corp"

    def test_malware_ref(self):
        """Test with malware object_ref."""
        lc = LanguageContent("malware--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
        lc.insert_content_strings("en", {"name": "Emotet"})
        json_str = lc.to_json()
        data = json.loads(json_str)

        assert data["object_ref"] == "malware--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        assert data["contents"]["en"]["name"] == "Emotet"
