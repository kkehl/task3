import pytest
from project.books.models import Book
from sqlalchemy.exc import DataError


@pytest.mark.parametrize("name, author, year_published, book_type", [
    ("The Left Hand of Darkness", "Ursula K. Le Guin", 1969, "Science Fiction"),
    ("A Canticle for Leibowitz", "Walter M. Miller Jr.", 1960, "Post-Apocalyptic"),
    ("The Long Way to a Small, Angry Planet", "Becky Chambers", 2014, "Space Opera"),
    ("The Shadow of the Wind", "Carlos Ruiz Zafón", 2001, "Mystery"),
    ("Fingersmith", "Sarah Waters", 2002, "Historical Thriller"),
    ("The City and the City", "China Miéville", 2009, "Weird Fiction"),
    ("A Fine Balance", "Rohinton Mistry", 1995, "Literary Fiction"),
    ("To Say Nothing of the Dog", "Connie Willis", 1997, "Science Fiction"),
    ("Good Omens", "Terry Pratchett & Neil Gaiman", 1990, "Comedy Fantasy"),
    ("The Goblin Emperor", "Katherine Addison", 2014, "Fantasy"),
    ("The Dispossessed", "Ursula K. Le Guin", 1974, "Science Fiction"),
    ("The Secret History", "Donna Tartt", 1992, "Mystery"),
    ("The Bone Clocks", "David Mitchell", 2014, "Fantasy"),
    ("A Tale for the Time Being", "Ruth Ozeki", 2013, "Contemporary Fiction"),
    ("Circe", "Madeline Miller", 2018, "Mythological Fiction"),
])
def test_create_valid_data(name, author, year_published, book_type):
    book = Book(name=name, author=author, year_published=year_published, book_type=book_type)

    assert book.name == name
    assert book.author == author
    assert book.year_published == year_published
    assert book.book_type == book_type


@pytest.mark.parametrize("name, author, year_published, book_type", [
    # Invalid name cases
    ("", "Ursula K. Le Guin", 1969, "Science Fiction"),  # Empty name
    (None, "Walter M. Miller Jr.", 1960, "Post-Apocalyptic"),  # Null name
    ("A" * 100, "Becky Chambers", 2014, "Space Opera"),  # Exceeds character limit

    # Invalid author cases
    ("The Left Hand of Darkness", "", 1969, "Science Fiction"),  # Empty author
    ("A Canticle for Leibowitz", None, 1960, "Post-Apocalyptic"),  # Null author
    ("The Long Way to a Small, Angry Planet", "A" * 100, 2014, "Space Opera"),  # Exceeds character limit

    # Invalid year cases
    ("The Shadow of the Wind", "Carlos Ruiz Zafón", -200, "Mystery"),  # Negative year
    ("Fingersmith", "Sarah Waters", 0, "Historical Thriller"),  # Year zero (invalid in most cases)
    ("The City and the City", "China Miéville", 3000, "Weird Fiction"),  # Unreasonably future year

    # Invalid book type cases
    ("A Fine Balance", "Rohinton Mistry", 1995, ""),  # Empty book type
    ("To Say Nothing of the Dog", "Connie Willis", 1997, None),  # Null book type
    ("Good Omens", "Terry Pratchett & Neil Gaiman", 1990, "A" * 50),  # Exceeds character limit

    # Multiple invalid fields
    ("", "", -100, ""),  # All fields invalid
    (None, None, None, None),  # Completely null fields
])
def test_create_invalid_data(name, author, year_published, book_type):
    with pytest.raises(DataError):
        book = Book(name=name, author=author, year_published=year_published, book_type=book_type)


@pytest.mark.parametrize("name, author, year_published, book_type", [
    # Mixed SQL Injection in Name
    ("'; DROP TABLE books; --", "Ursula K. Le Guin", 1969, "Science Fiction"),
    ("The Shadow of the Wind", "Carlos Ruiz Zafón", 2001, "\" OR \"\"=\""),
    ("Robert'); DROP TABLE books;--", "China Miéville", 2009, "Weird Fiction"),
    ("The Long Way to a Small, Angry Planet", "Becky Chambers", 2014, "1; EXEC xp_cmdshell('dir')"),

    # Mixed SQL Injection in Author
    ("The Dispossessed", "'; DROP TABLE authors; --", 1974, "Science Fiction"),
    ("A Canticle for Leibowitz", "\" OR \"\"=\"", 1960, "Post-Apocalyptic"),
    ("Fingersmith", "Robert'); DROP TABLE books;--", 2002, "Historical Thriller"),
    ("Good Omens", "1; EXEC xp_cmdshell('shutdown')", 1990, "Comedy Fantasy"),

    # Mixed SQL Injection in Year
    ("Circe", "Madeline Miller", "0 OR 1=1", "Mythological Fiction"),
    ("The Goblin Emperor", "Katherine Addison", "Robert'); DROP TABLE books;--", "Fantasy"),
    ("A Fine Balance", "Rohinton Mistry", "1; DROP TABLE books", "Literary Fiction"),
    ("To Say Nothing of the Dog", "Connie Willis", "\" OR \"\" = \"", "Science Fiction"),

    # Mixed SQL Injection in Book Type
    ("The City and the City", "China Miéville", 2009, "'; DROP TABLE book_types; --"),
    ("The Bone Clocks", "David Mitchell", 2014, "\" OR \"\"=\""),
    ("A Tale for the Time Being", "Ruth Ozeki", 2013, "Robert'); DROP TABLE books;--"),
    ("The Left Hand of Darkness", "Ursula K. Le Guin", 1969, "1; EXEC xp_cmdshell('whoami')")
])
def test_sql_injection_creation_less_common(name, author, year_published, book_type):
    with pytest.raises(DataError):
        book = Book(name=name, author=author, year_published=year_published, book_type=book_type)


@pytest.mark.parametrize("name, author, year_published, book_type", [
    # JavaScript Injection in Name
    ("<script>alert('Name')</script>", "Ursula K. Le Guin", 1969, "Science Fiction"),
    ("The Shadow of the Wind", "Carlos Ruiz Zafón", 2001, "<img src=x onerror=alert('Name')>"),
    ("Robert');</script><script>alert('Name')</script>", "China Miéville", 2009, "Weird Fiction"),
    ("The Long Way to a Small, Angry Planet", "Becky Chambers", 2014, "<svg onload=alert('Name')>"),

    # JavaScript Injection in Author
    ("The Dispossessed", "<script>alert('Author')</script>", 1974, "Science Fiction"),
    ("A Canticle for Leibowitz", "<img src=x onerror=alert('Author')>", 1960, "Post-Apocalyptic"),
    ("Fingersmith", "Robert');</script><script>alert('Author')</script>", 2002, "Historical Thriller"),
    ("Good Omens", "<svg onload=alert('Author')>", 1990, "Comedy Fantasy"),

    # JavaScript Injection in Year
    ("Circe", "Madeline Miller", "<script>alert('Year')</script>", "Mythological Fiction"),
    ("The Goblin Emperor", "Katherine Addison", "<img src=x onerror=alert('Year')>", "Fantasy"),
    ("A Fine Balance", "Rohinton Mistry", "<svg onload=alert('Year')>", "Literary Fiction"),
    ("To Say Nothing of the Dog", "Connie Willis", "Robert');</script><script>alert('Year')</script>",
     "Science Fiction"),

    # JavaScript Injection in Book Type
    ("The City and the City", "China Miéville", 2009, "<script>alert('Type')</script>"),
    ("The Bone Clocks", "David Mitchell", 2014, "<img src=x onerror=alert('Type')>"),
    ("A Tale for the Time Being", "Ruth Ozeki", 2013, "<svg onload=alert('Type')>"),
    ("The Left Hand of Darkness", "Ursula K. Le Guin", 1969, "Robert');</script><script>alert('Type')</script>")
])
def test_javascript_injection(name, author, year_published, book_type):
    with pytest.raises(DataError):
        book = Book(name=name, author=author, year_published=year_published, book_type=book_type)


@pytest.mark.parametrize("name, author, year_published, book_type", [
    # Extreme Name Lengths
    ("A" * 1000000, "Ursula K. Le Guin", 1969, "Science Fiction"),  # Extremely long name
    ("!@#$%^&*()_+{}:\"<>?[];',./", "Carlos Ruiz Zafón", 2001, "Mystery"),  # Special characters
    ("\n\t\r", "China Miéville", 2009, "Weird Fiction"),  # Whitespace characters
    ("", "Becky Chambers", 2014, "Science Fiction"),  # Empty string

    # Extreme Author Lengths
    ("Circe", "B" * 1000000, 2018, "Mythological Fiction"),  # Extremely long author name
    ("The Goblin Emperor", "!@#$%^&*()_+{}:\"<>?[];',./", 2014, "Fantasy"),  # Special characters
    ("A Fine Balance", "\n\t\r", 1995, "Literary Fiction"),  # Whitespace characters
    ("To Say Nothing of the Dog", "", 1998, "Comedy Science Fiction"),  # Empty string

    # Extreme Year Values
    ("The City and the City", "China Miéville", -9999999999999, "Speculative Fiction"),  # Negative year
    ("The Bone Clocks", "David Mitchell", 99999999999999999, "Science Fiction"),  # Very large year
    ("A Tale for the Time Being", "Ruth Ozeki", 0, "Historical Fiction"),  # Zero as year
    ("The Left Hand of Darkness", "Ursula K. Le Guin", None, "Science Fiction"),  # None as year

    # Extreme Book Type
    ("The Shadow of the Wind", "Carlos Ruiz Zafón", 2001, "T" * 1000000),  # Extremely long type
    ("Fingersmith", "Sarah Waters", 2002, "!@#$%^&*()_+{}:\"<>?[];',./"),  # Special characters
    ("Good Omens", "Terry Pratchett & Neil Gaiman", 1990, "\n\t\r"),  # Whitespace characters
    ("A Canticle for Leibowitz", "Walter M. Miller Jr.", 1960, ""),  # Empty string
])
def test_extreme_values(name, author, year_published, book_type):
    with pytest.raises(DataError):
        book = Book(name=name, author=author, year_published=year_published, book_type=book_type)
