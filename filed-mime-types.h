	switch (filed_hash((const unsigned char *) p, 16777259)) {
		case 21351:
			if (strcmp(p, "htm") == 0) {
				return("text/html");
			}
			return(FILED_DEFAULT_TYPE);
		case 23652:
			if (strcmp(p, "mp4") == 0) {
				return("video/mp4");
			}
			return(FILED_DEFAULT_TYPE);
		case 23653:
			if (strcmp(p, "mp3") == 0) {
				return("audio/mpeg");
			}
			return(FILED_DEFAULT_TYPE);
		case 24100:
			if (strcmp(p, "txt") == 0) {
				return("test/plain");
			}
			return(FILED_DEFAULT_TYPE);
		case 24335:
			if (strcmp(p, "zip") == 0) {
				return("application/zip");
			}
			return(FILED_DEFAULT_TYPE);
		case 170809:
			if (strcmp(p, "html") == 0) {
				return("text/html");
			}
			return(FILED_DEFAULT_TYPE);
		case 189115:
			if (strcmp(p, "mpg4") == 0) {
				return("video/mp4");
			}
			return(FILED_DEFAULT_TYPE);
		case 189116:
			if (strcmp(p, "mpg3") == 0) {
				return("audio/mpeg");
			}
			return(FILED_DEFAULT_TYPE);
		case 193372:
			if (strcmp(p, "text") == 0) {
				return("test/plain");
			}
			return(FILED_DEFAULT_TYPE);
	}
