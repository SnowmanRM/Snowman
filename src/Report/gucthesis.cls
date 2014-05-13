%% 'gucmasterthesis.cls' - a LaTeX class for master's theses at GUC
%%
%% Copyright (C) 2005 Ivar Farup and Kjetil Orbekk
%%
%% CHANGE LOG:
%%
%% v0.1 2005/03/09:
%%
%%  * First pre-alpha draft
%%
%% v0.2 2005/03/10:
%%
%%  * Reduced size of heading to 7pt
%%
%%  * Reimplemented the heading without using fancyhdr, making the
%%    package (more) compatible with hyperref.
%%
%%  * Introduced \thesisdate for upper right header
%%
%% v0.3 2005/03/11:
%%
%%  * \chapter{} and \chapter*{} heading can cover several lines
%%
%% v0.4 2005/04/19:
%%
%%  * new itemize and enumerate environments
%%
%%  * twoside, adjusted headers and margins; header and footers are
%%    not shown on pages that are empty due to new chapters
%%
%%  * \thesistitlepage: dummy title page using new commands
%%    \thesisauthor, \thesisdate, and \thesistitle
%%
%%  * no centering of sections
%%
%%  * \subsubsection and \paragraph now produce an error message
%%
%% v0.5 2005/05/10:
%%
%%  * \subsubsection and \paragraph reintroduced
%%
%%  * \parskip and \parindent changed
%%
%% v0.6 2005/05/13:
%%
%%  * \chapter no longer in capitals
%%
%% v0.7 2007/05/30:
%%
%%  * Added frontpage matter implemented by Kjetil Orbekk
%%
%%  * Fixed compatibility problem with hyperref using \phantomsection
%%    as suggested by Halvor Borgen
%%
%% v0.8 2008/05/20
%%
%%  * Options oneside and twoside added by Rune Hammersland
%%
%% v0.9 2010/04/20
%%  * Warning about page numbers (pdflatex) fixed by defining 
%%     the title page format
%%  * Added a spill programmering option
%%
%% v1.0 2011/01/18
%%  * Added infosek-bachelor, ingeni�r
%%
%% v1.01 2011/05/10
%%  * fixed front cover for both oneside and twoside
%%
%%
%% TODO:
%%
%%  * Capitals for chapters in toc.
%%
%%  * Other fonts for tt, sf etc.?
%%
%%  * Problems with nested itemize environments
%%
%%  * Font warnings (pdflatex)
%%

%% MACRO
\newcommand{\GUC}{{G}j\o{}vik {U}niversity {C}ollege} %the extra {'s protect upper case
\newcommand{\HiG}{{H}\o{}gskolen i {G}j\o{}vik}




%% IDENTIFICATION

\xdef\gucthesisdate{2011/05/10}
\xdef\gucthesisversion{1.01}
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{gucthesis}
  [\gucthesisdate\space
   v\gucthesisversion\space
   Copyright (C) 2011 Ivar Farup and Simon McCallum]

%% CLASS FILE COMMANDS

\LoadClass[a4paper]{report}

%% PACKAGE LOADING

\RequirePackage{geometry}
\RequirePackage[T1]{fontenc}
\RequirePackage{charter}
\RequirePackage{euler}
\RequirePackage{lastpage}
\RequirePackage{babel}
%\RequirePackage[absolute]{textpos}



%% MAIN PART

% Page geometry and layout
%\setlength{\TPHorizModule}{30mm}
%\setlength{\TPVertModule}{\TPHorizModule}
%\textblockorigin{10mm}{10mm}


\AtBeginDocument{\baselineskip=14pt%
  \parskip=0pt%
  \parindent=14pt%
  \frenchspacing%
  \setcounter{secnumdepth}{2}%
}
\pagenumbering{roman}           % until first chapter, see below

% Header and footer

\def\thesis@title{Use thesistitle to insert your title here.}
\def\thesis@date{Use thesisdate to insert your date here.}
\def\thesis@author{Use thesisauthor to insert your name here.}
\def\thesis@authorA{}
\def\thesis@authorB{}
\def\thesis@authorC{}
\def\thesis@supervisor{}
\def\thesis@supervisorA{}
\def\thesis@oppdragsgiver{}

\def\gmt@keywords{}
\def\gmt@desc{}


\def\thesis@titleNOR{Use thesistitle to insert your title here.}
\def\gmt@keywordsNOR{}
\def\gmt@descNOR{}

\def\gmt@number{}
\def\gmt@contact{}
\def\gmt@appnumber{}
\def\gmt@pagecount{}

\def\thesistitle#1{\def\thesis@title{#1}}
\def\thesisdate#1{\def\thesis@date{#1}}
\def\thesisauthor#1{\def\thesis@author{#1}}
\def\thesisauthorA#1{\def\thesis@authorA{#1}}
\def\thesisauthorB#1{\def\thesis@authorB{#1}}
\def\thesisauthorC#1{\def\thesis@authorC{#1}}
\def\thesissupervisor#1{\def\thesis@supervisor{#1}}
\def\thesissupervisorA#1{\def\thesis@supervisorA{#1}}
\def\gmtoppdragsgiver#1{\def\thesis@oppdragsgiver{#1}}


\def\gmtkeywords#1{\def\gmt@keywords{#1}}
\def\gmtdesc#1{\def\gmt@desc{#1}}


\def\gmtkeywordsNOR#1{\def\gmt@keywordsNOR{#1}}
\def\gmtdescNOR#1{\def\gmt@descNOR{#1}}
\def\thesistitleNOR#1{\def\thesis@titleNOR{#1}}


\def\gmtnumber#1{\def\gmt@number{#1}}
\def\gmtbachelornumber#1{\def\gmt@number{#1}}
\def\gmtcontact#1{\def\gmt@contact{#1}}
\def\gmtappnumber#1{\def\gmt@appnumber{#1}}
\def\gmtpagecount#1{\def\gmt@pagecount{#1}}

\def\ps@gucheadings{%
  \def\@oddfoot{\reset@font\hfil\thepage\hfil}
  \def\@oddhead{\underline{\hbox
      to\hsize{\fontsize{7}{9}\selectfont\hfil\thesis@title}}}
  \def\@evenhead{\underline{\hbox
      to\hsize{\fontsize{7}{9}\selectfont\thesis@title\hfil}}}
  \let\@evenfoot=\@oddfoot}
\pagestyle{gucheadings}
% Empty page does not have header or footer
\def\cleardoublepage{\clearpage\if@twoside \ifodd\c@page\else
    \hbox{}\thispagestyle{empty}\newpage\if@twocolumn\hbox{}\newpage\fi\fi\fi}

\newif\if@masters

% Title page

%%\def\@subtitle{\relax}
%%\newcommand{\subtitle}[1]{\gdef\@subtitle{#1}}
%%\renewcommand{\maketitle}{
%%	\newpage
%%	\null
%%	\vskip 2em%
%%	\begin{center}%
%%	\let \footnote \thanks
%%	{\LARGE \@title \par}%
%%	\vskip 1.5em%
%%	{\large
%%		\lineskip .5em%
%%		\begin{tabular}[t]{c}%
%%		\@author
%%		\end{tabular}\par}%
%%	\vskip 1em%
%%	{\large \@date}%
%%	\end{center}%
%%	\par
%%	\vskip 1.5em
%%}



\def\thesistitlepage{
  \title{\thesis@title}
  \date{\thesis@date}
  \author{\thesis@author \\ \thesis@authorA}
  \maketitle
}

% Sectioning commands

\def\section{\@startsection
  {section}%
  {1}%
  {0mm}%
  {-10pt}%
  {4pt}%
  {\normalfont\fontsize{12}{14}\selectfont\bfseries}%
}
   
\def\subsection{\@startsection
  {subsection}%
  {2}%
  {0mm}%
  {-6pt}%
  {2pt}%
  {\normalfont\fontsize{10.5}{14}\selectfont\bfseries}%
}

\def\subsubsection{\@startsection
  {subsubsection}%
  {3}%
  {0mm}%
  {-6pt}%
  {2pt}%
  {\normalfont\normalsize\selectfont\bfseries}%
}

\def\paragraph{\@startsection
  {paragraph}%
  {4}%
  {0mm}%
  {-6pt}%
  {2pt}%
  {\normalfont\normalsize\selectfont\itshape}%
}

\newcounter{firstchapter}       % hack to find out where to start
\c@firstchapter=1               % arabic page numbering, see below

\newcounter{tmpfig}             % hack to have continuous numbering of
\newcounter{tmptab}             % figures and tables, see below

\newcounter{numapp}
\newcommand{\numberofapp}{%
    \immediate\write\@auxout%
      {\string\setcounter{numapp}{\the\c@chapter}}%
}



\renewcommand\chapter{%\if@openright\cleardoublepage\else\clearpage\fi
  \cleardoublepage
%  \thispagestyle{plain}%
  \global\@topnum\z@
  \@afterindentfalse
  \secdef\@chapter\@schapter}
\def\@chapter[#1]#2{\ifnum \c@secnumdepth >\m@ne
  \c@tmpfig=\c@figure           % hack for figure and table numbering
  \c@tmptab=\c@table
  \refstepcounter{chapter}%
  \c@figure=\c@tmpfig
  \c@table=\c@tmptab
  \ifnum\c@firstchapter = 1     % hack for page numbering
  \pagenumbering{arabic}
  \c@page=1 \c@firstchapter=0
  \fi
  \typeout{\@chapapp\space\thechapter.}%
  \phantomsection
  \addcontentsline{toc}{chapter}%
  {\protect\numberline{\thechapter}#1}%
  \else
  \phantomsection
  \addcontentsline{toc}{chapter}{#1}%
  \fi
  \chaptermark{#1}%
% Add extra space in list of figures and list of tables between
% figures & tables belonging to different chapters:
%  \addtocontents{lof}{\protect\addvspace{10\p@}}%
%  \addtocontents{lot}{\protect\addvspace{10\p@}}%
  \if@twocolumn
  \@topnewpage[\@makechapterhead{{#2}}]%
  \else
  \@makechapterhead{{#2}}%
  \@afterheading
  \fi}
\def\@makechapterhead#1{%
  \vspace*{24\p@}%
  {\parindent \z@ \raggedright \normalfont
    \ifnum \c@secnumdepth >\m@ne
    \begin{center}
    \normalfont\fontsize{14}{14}\selectfont\bfseries\thechapter
    \fi
    \normalfont\fontsize{14}{14}\selectfont\bfseries\quad #1
    \end{center}\par\nobreak
    \vskip 12\p@
  }}
\def\@schapter#1{\if@twocolumn
  \@topnewpage[\@makeschapterhead{{#1}}]%
  \else
  \@makeschapterhead{{#1}}%
  \@afterheading
  \fi
  \phantomsection
  \addcontentsline{toc}{chapter}{#1}% Contentsline also for \chapter*
}
\def\@makeschapterhead#1{%
  \vspace*{24\p@}%
  {\parindent \z@ \raggedright
    \normalfont
    \interlinepenalty\@M
    \begin{center}\fontsize{14}{14} \bfseries  #1\end{center}\par\nobreak
    \vskip 12\p@
  }}

% Table of contents

\def\l@chapter#1#2{\@dottedtocline{1}{0em}{1.5em}{\bf #1}{\bf #2}}

% Table and figure captions

\long\def\@makecaption#1#2{%
  \vskip\abovecaptionskip
  \sbox\@tempboxa{\fontsize{9}{13}\selectfont #1: #2}%
  \ifdim \wd\@tempboxa >\hsize
    \fontsize{9}{13}\selectfont #1: #2\par
  \else
    \global \@minipagefalse
    \hb@xt@\hsize{\hfil\box\@tempboxa\hfil}%
  \fi
  \vskip\belowcaptionskip}

% Table and figure numbering without chapter number

\def\thefigure{\@arabic\c@figure}
\def\thetable{\@arabic\c@table}

% Quotes

\renewenvironment{quote}
{\list{}{\rightmargin\leftmargin\fontsize{9}{12}\selectfont}%
\item\relax}
{\endlist}

% Lists (itemize and enumerate)

% \renewenvironment{itemize}{\begin{list}{\ensuremath\bullet}%
%     {\labelwidth=.5em%
%       \labelsep=1em%
%       \leftmargin=\labelwidth%
%       \advance\leftmargin\labelsep%
%       \rightmargin=0pt%
%       \topsep=5pt%
%       \parsep=0pt%
%       \partopsep=\baselineskip%
%       \itemsep=\topsep%
%       }}{\end{list}}

% \newcounter{nenum}
% \renewenvironment{enumerate}{\begin{list}{\llap{\arabic{nenum}.}}%
%      {\usecounter{nenum}%
%       \labelwidth=.7em%
%       \labelsep=.8em%
%       \leftmargin=\labelwidth%
%       \advance\leftmargin\labelsep%
%       \rightmargin=0pt%
%       \topsep=5pt%
%       \parsep=0pt%
%       \partopsep=0pt%
%       \itemsep=\topsep%
%       }%
%    }{\end{list}}

%%
%% GMT Frontpage by Kjetil:
%%

\newcommand{\gmt@frontpagesyear}{%
Use $\backslash$useyear\{<year>\} to set year.
}

\newcommand{\useyear}[1]{%
  \renewcommand{\gmt@frontpagesyear}{#1}
}


\newcommand\gmt@firstpagetext{%
  \noindent Use this class with options\\ 
  ``MMT'' Masters i Medieteknikk,\\
  ``MIS'' Masters i Informasjonssikkerhet,\\
  ``CIMET'' Erasmus mundus Masters in Colour Science,\\
  ``BSP'' Bachelor i Spillprogrammering,\\
  ``BRD'' Bachelor i drift av nettverk og datasystemer,\\
  ``BIS'' Bachelor i Informasjonssikkerhet,\\
  ``BPU'' Bachelor i Programvareutvikling, \\
  ``BIND'' Bachelor i Ingeni�rfad - data. 
}

\newcommand\gmt@secondpagetext{%
  \noindent Use this class with options\\ 
  ``MMT'' Masters i Medieteknikk,\\
  ``MIS'' Masters i Informasjonssikkerhet,\\
  ``CIMET'' Erasmus mundus Masters in Colour Science,\\
  ``BSP'' Bachelor i Spillprogrammering,\\
  ``BRD'' Bachelor i drift av nettverk og datasystemer,\\
  ``BIS'' Bachelor i Informasjonssikkerhet,\\
  ``BPU'' Bachelor i Programvareutvikling, \\
  ``BIND'' Bachelor i Ingeni�r. 
}

\newcommand\gmt@imttext{%
  \noindent
  Avdeling for\\
  informatikk og medieteknikk\\
  H\o{}gskolen i Gj\o{}vik\\
  Postboks 191\\
  2802 Gj\o{}vik

  \vskip 3em%

  \noindent
  Department of Computer Science\\
  and Media Technology\\
  Gj\o{}vik University College\\
  Box 191\\
  N-2802 Gj\o{}vik\\
  Norway
}

	    



%% OPTIONS (declare more here if needed)

\DeclareOption{oneside}{\@twosidefalse \@mparswitchfalse%
\geometry{a4paper, left=3.75cm, right=3.75cm, top=3cm, bottom=4cm,
  head=1.2cm, foot=2cm}}
\DeclareOption{twoside}{\@twosidetrue  \@mparswitchtrue%
\geometry{a4paper, left=4.5cm, right=3cm, top=3cm, bottom=4cm,
  head=1.2cm, foot=2cm}}

\newif\if@norsk
\newif\if@english


\DeclareOption{norsk}{
   \@norskrue 
   \@englishfalse
}

\DeclareOption{english}{
   \@englishtrue 
   \@norskfalse
}

	\newcommand\gmt@CollegeNameText{%
		Department of Computer Science and Media Technology\\
		Gj\o{}vik University College, 
	}
	
 \if@norsk
	\renewcommand\gmt@CollegeNameText{%
	  	Avdeling for informatikk og medieteknikk\\
	 	  H\o{}gskolen i Gj\o{}vik, 
	}  
\fi

\DeclareOption{BSP}{%
  \renewcommand\gmt@firstpagetext{%
    \begin{tabular}{ccc}
	Bacheloroppgave&&\\
    	Bachelor i &Spill &Programmering\\
    	20 &ECTS&\\
    	Avdeling for& informatikk &og medieteknikk\\
    	H\o{}gskolen &i Gj\o{}vik, &\gmt@frontpagesyear\\
    \end{tabular}
  }
  \renewcommand\gmt@secondpagetext{\gmt@imttext}
}

\DeclareOption{BRD}{%
  \renewcommand\gmt@firstpagetext{%
    \begin{tabular}{ccc}
	Bacheloroppgave&&\\
    	Bachelor i & drift av nettverk & og datasystemer \\
    	20 &ECTS&\\
    	Avdeling for& informatikk &og medieteknikk\\
    	H\o{}gskolen &i Gj\o{}vik, &\gmt@frontpagesyear\\
    \end{tabular}
  }
  \renewcommand\gmt@secondpagetext{\gmt@imttext}
}

\DeclareOption{BIND}{%
  \renewcommand\gmt@firstpagetext{%
    \begin{tabular}{ccc}
	Bacheloroppgave&&\\
    	Bachelor i & ingeni�rfag � data &  \\
    	20 &ECTS&\\
    	Avdeling for& informatikk &og medieteknikk\\
    	H\o{}gskolen &i Gj\o{}vik, &\gmt@frontpagesyear\\
    \end{tabular}
  }
  \renewcommand\gmt@secondpagetext{\gmt@imttext}
}

\DeclareOption{BIS}{%
  \renewcommand\gmt@firstpagetext{%
    \begin{tabular}{ccc}
	Bacheloroppgave&&\\
    	Bachelor i & informasjonssikkerhet &  \\
    	20 &ECTS&\\
    	Avdeling for& informatikk &og medieteknikk\\
    	H\o{}gskolen &i Gj\o{}vik, &\gmt@frontpagesyear\\
    \end{tabular}
  }
  \renewcommand\gmt@secondpagetext{\gmt@imttext}
}

\DeclareOption{BPU}{%

  \renewcommand\gmt@firstpagetext{%
    \begin{tabular}{ccc}
	Bacheloroppgave&&\\
    	Bachelor i & programvareutvikling &  \\
    	20 &ECTS&\\
    	Avdeling for& informatikk &og medieteknikk\\
    	H\o{}gskolen &i Gj\o{}vik, &\gmt@frontpagesyear\\
    \end{tabular}
  }
  \renewcommand\gmt@secondpagetext{\gmt@imttext}
}


\DeclareOption{MMT}{%
  \@masterstrue
  \if@norsk
  	\renewcommand\gmt@firstpagetext{%
  	  Masteroppgave\\
  	  Master i Teknologi - Medieteknikk\\
	   30 ECTS\\
	  \gmt@CollegeNameText
 	}
  \else
	\renewcommand\gmt@firstpagetext{%
	   Master's Thesis\\
	   Master of Science in Media Technology\\
	   30 ECTS\\
	   \gmt@CollegeNameText
	 }
  \fi
  \renewcommand\gmt@secondpagetext{\gmt@imttext}
}


\DeclareOption{MIS}{%
  \@masterstrue
  \if@norsk  
	\renewcommand\gmt@firstpagetext{%
    	  Masteroppgave\\
    	  Master i informasjonssikkerhet\\
	  30 ECTS\\
	  \gmt@CollegeNameText \gmt@frontpagesyear 
	}
  \else
	\renewcommand\gmt@firstpagetext{%
 	  Master's Thesis\\
    	  Master of Science in Information Security\\
  	  30 ECTS\\
 	  \gmt@CollegeNameText \gmt@frontpagesyear 
	}
  \fi
  \renewcommand\gmt@secondpagetext{\gmt@imttext}
% \def@masters
}

\DeclareOption{CIMET}{% not implemented yet
  \@masterstrue
  \if@norsk  
	\renewcommand\gmt@firstpagetext{%
    	  Only english for CIMET thesis\\
	\\
	}
  \else
	\renewcommand\gmt@firstpagetext{%
 	  Master's Thesis\\
    	  Master In Colour science\\
       	  30 ECTS\\
	  \gmt@CollegeNameText
	}
  \fi
  \renewcommand\gmt@secondpagetext{\gmt@imttext}
}

\ProcessOptions\relax

%% FRONTPAGE GENERATION
\newcommand\makefrontpages{%
	\if@masters
	  \makemastersfrontpages
	\else
		\makebachelorfrontpages
	\fi
}


\newcommand\makemastersfrontpages{%
  \begin{titlepage}%
    %\thispagestyle{empty}
    %\setcounter{page}\z@
    \let\footnotesize\small
    \let\footnoterule\relax
    \let \footnote \thanks
    \null\vfil
    \vskip 165\p@
    \begin{center}%
      {\fontsize{20}{24}\selectfont \thesis@title}%
      \vskip 3em%
      {%\large
        \lineskip .75em%
        \begin{tabular}[t]{c}%
          {\fontsize{14}{16}\selectfont \thesis@author \par} %\@author
        \end{tabular}\par}%
      % \vskip 1.5em%
      % {\large Dato \par}%       % Set date in \large size.
    \end{center}\par
    \@thanks
    \vfill
    \vskip 3em
    \begin{center}%
      \includegraphics[width=70pt]{higlogo} \\
      \medskip
      \gmt@firstpagetext
    \end{center}
  \end{titlepage}

  \newpage
  \thispagestyle{empty}
  \null\vfil
  \vfill
  \vbox{\footnotesize{\gmt@secondpagetext}}
}

\newcommand\makebachelorfrontpages{%
  \begin{titlepage}%
    %\thispagestyle{empty}
    %\setcounter{page}\z@

    \let\footnotesize\small
    \let\footnoterule\relax
    \let \footnote \thanks
    \vspace*{6.9mm}
    {%
    \fontsize{14}{16}\selectfont 
    BACHELOROPPGAVE:\\
	\par}
    \hspace*{-5mm}
{

    \hspace{-5mm} \includegraphics[width=130mm,height=70mm]{greybackground} \\ %should be 127 and 67 but front cover wrong
      \vskip -5.5cm % 7 gets to the top of the box
      
        \begin{tabular}[10cm]{p{0.5cm}p{10.2cm}l}%
          &{\fontsize{14}{16}\selectfont \textbf{\thesis@title} \par} &\rule[-7cm]{0cm}{7cm}
        \end{tabular}

\par}
   \fontsize{14}{16}\selectfont 
   FORFATTERE:\\
   \begin{tabular}[10cm]{p{1.5cm}l}%
          \rule[-4cm]{0cm}{4cm}&{\fontsize{14}{16}\selectfont 
          \parbox{6cm}{\thesis@author \\
          \thesis@authorA \\
          \thesis@authorB \\
          \thesis@authorC \\
          
          } 
          \par}
        \end{tabular}\par
  DATO: \\
  \hspace*{21.5mm}{\fontsize{14}{16}\selectfont {\gmt@frontpagesyear} \par}
  \end{titlepage}

 \cleardoublepage
  
  \newpage
  {%
    \fontsize{14}{16}\selectfont 
    Sammendrag av Bacheloroppgaven\\
	\par}
%\addcontentsline{toc}{chapter}{Summary}
%\thispagestyle{empty}
\begin{tabular}{|l@{  }p{0.2\textwidth}|l|l|l|}
		\hline
	  Tittel: & \multicolumn{3}{@{}p{0.6\textwidth}|}{\thesis@titleNOR} & Nr: \gmt@number \\
		\cline{2-5}
		& \multicolumn{3}{@{  }l|}{} & Dato: \gmt@frontpagesyear\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{}\\
		\hline
		Deltakere: & \multicolumn{4}{@{  }l|}{\thesis@author}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{\thesis@authorA}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{\thesis@authorB}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{\thesis@authorC}\\
		\hline
		Veiledere: & \multicolumn{4}{@{\thesis@supervisor}l|}{}\\
		\cline{2-5}
		 & \multicolumn{4}{@{  }l|}{\thesis@supervisorA}\\
		\hline
		Oppdragsgiver: & \multicolumn{4}{@{  }l|}
       {\thesis@oppdragsgiver}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{}\\
		\hline
		Kontaktperson: & \multicolumn{4}{@{  }p{0.6\textwidth}|}{\gmt@contact}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{}\\
		\hline
		Stikkord & \multicolumn{4}{@{  }l|}
        {\gmt@keywordsNOR}\\
		\cline{2-5}
		& \multicolumn{4}{@{}l|}{}\\
		\hline
		\multicolumn{2}{|p{0.18\textwidth}|}{Antall sider: \pageref{LastPage}} & Antall vedlegg: \gmt@appnumber & \multicolumn{2}
       {|l|}{Tilgjengelighet: \AA{}pen}\\
		\hline
		\multicolumn{5}{|l|}{Kort beskrivelse av bacheloroppgaven:}\\
		\multicolumn{5}{|p{1.0\textwidth}|}{\gmt@descNOR}\\
		\hline
  \end{tabular}

% this should be a function call so that the layout is done in a single place. This is currently bad coding but I do not have time to fix it at the moment.  I will fix this later.
\cleardoublepage
  
  \newpage
  {%
    \fontsize{14}{16}\selectfont 
    Summary of Graduate Project\\
	\par}
%\addcontentsline{toc}{chapter}{Summary}
%\thispagestyle{empty}
\begin{tabular}{|l@{  }p{0.2\textwidth}|l|l|l|}
		\hline
	  Title: & \multicolumn{3}{@{}p{0.6\textwidth}|}{\thesis@title} & Nr: \gmt@number \\
		\cline{2-5}
		& \multicolumn{3}{@{  }l|}{} & Date: \gmt@frontpagesyear\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{}\\
		\hline
		Participants: & \multicolumn{4}{@{  }l|}{\thesis@author}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{\thesis@authorA}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{\thesis@authorB}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{\thesis@authorC}\\
		\hline
		Supervisor: & \multicolumn{4}{@{\thesis@supervisor}l|}{}\\
		\cline{2-5}
		 & \multicolumn{4}{@{  }l|}{\thesis@supervisorA}\\
		\hline
		Employer: & \multicolumn{4}{@{  }l|}
       {\thesis@oppdragsgiver}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{}\\
		\hline
		Contact person: & \multicolumn{4}{@{  }p{0.6\textwidth}|}{\gmt@contact}\\
		\cline{2-5}
		& \multicolumn{4}{@{  }l|}{}\\
		\hline
		Keywords & \multicolumn{4}{@{  }l|}
        {\gmt@keywords}\\
		\cline{2-5}
		& \multicolumn{4}{@{}l|}{}\\
		\hline
		\multicolumn{2}{|p{0.18\textwidth}|}{Pages: \pageref{LastPage}} & Appendixes: \gmt@appnumber & \multicolumn{2}
       {|l|}{Availability: Open}\\
		\hline
		\multicolumn{5}{|l|}{Short description of the main project:}\\
		\multicolumn{5}{|p{1.0\textwidth}|}{\gmt@desc}\\
		\hline
  \end{tabular}


}
